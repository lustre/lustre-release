/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
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
 *  Storage Target Handling functions
 *  Lustre Object Server Module (OST)
 *
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OST

#include <linux/module.h>
#include <linux/obd_ost.h>
#include <linux/lustre_net.h>
#include <linux/lustre_dlm.h>

static int ost_destroy(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_destroy(conn, &body->oa, NULL);
        RETURN(0);
}

static int ost_getattr(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_getattr(conn, &repbody->oa);
        RETURN(0);
}

static int ost_statfs(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct obd_statfs *osfs;
        struct statfs sfs;
        int rc, size = sizeof(*osfs);
        ENTRY;

        rc = obd_statfs(conn, &sfs);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                req->rq_status = rc;
                RETURN(rc);
        }

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        osfs = lustre_msg_buf(req->rq_repmsg, 0);
        memset(osfs, 0, size);
        obd_statfs_pack(osfs, &sfs);
        RETURN(0);
}

static int ost_open(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_open(conn, &repbody->oa, NULL);
        RETURN(0);
}

static int ost_close(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_close(conn, &repbody->oa, NULL);
        RETURN(0);
}

static int ost_create(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_create(conn, &repbody->oa, NULL);
        RETURN(0);
}

static int ost_punch(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_punch(conn, &repbody->oa, NULL, 
                                   repbody->oa.o_blocks, repbody->oa.o_size);
        RETURN(0);
}

static int ost_setattr(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_setattr(conn, &repbody->oa);
        RETURN(0);
}

static int ost_brw_read(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ptlrpc_bulk_desc *desc;
        void *tmp1, *tmp2, *end2;
        struct niobuf_remote *remote_nb;
        struct niobuf_local *local_nb = NULL;
        struct obd_ioobj *ioo;
        struct ost_body *body;
        int rc, cmd, i, j, objcount, niocount, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        end2 = (char *)tmp2 + req->rq_reqmsg->buflens[2];
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        niocount = req->rq_reqmsg->buflens[2] / sizeof(*remote_nb);
        cmd = OBD_BRW_READ;

        for (i = 0; i < objcount; i++) {
                ost_unpack_ioo(&tmp1, &ioo);
                if (tmp2 + ioo->ioo_bufcnt > end2) {
                        LBUG();
                        GOTO(out, rc = -EFAULT);
                }
                for (j = 0; j < ioo->ioo_bufcnt; j++)
                        ost_unpack_niobuf(&tmp2, &remote_nb);
        }

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);
        OBD_ALLOC(local_nb, sizeof(*local_nb) * niocount);
        if (local_nb == NULL)
                RETURN(-ENOMEM);

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        req->rq_status = obd_preprw(cmd, conn, objcount,
                                    tmp1, niocount, tmp2, local_nb, NULL);

        if (req->rq_status)
                GOTO(out_local, 0);

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(out_local, rc = -ENOMEM);
        desc->b_portal = OST_BULK_PORTAL;

        for (i = 0; i < niocount; i++) {
                struct ptlrpc_bulk_page *bulk;
                bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(out_bulk, rc = -ENOMEM);
                remote_nb = &(((struct niobuf_remote *)tmp2)[i]);
                bulk->b_xid = remote_nb->xid;
                bulk->b_buf = (void *)(unsigned long)local_nb[i].addr;
                bulk->b_buflen = PAGE_SIZE;
        }

        rc = ptlrpc_send_bulk(desc);
        if (rc)
                GOTO(out_bulk, rc);

#warning OST must time out here.
        wait_event(desc->b_waitq, ptlrpc_check_bulk_sent(desc));
        if (desc->b_flags & PTL_RPC_FL_INTR)
                rc = -EINTR;

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        req->rq_status = obd_commitrw(cmd, conn, objcount,
                                      tmp1, niocount, local_nb, NULL);

out_bulk:
        ptlrpc_free_bulk(desc);
out_local:
        OBD_FREE(local_nb, sizeof(*local_nb) * niocount);
out:
        if (rc)
                ptlrpc_error(req->rq_svc, req);
        else
                ptlrpc_reply(req->rq_svc, req);
        RETURN(rc);
}

static int ost_brw_write(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = (struct lustre_handle *)req->rq_reqmsg;
        struct ptlrpc_bulk_desc *desc;
        struct niobuf_remote *remote_nb;
        struct niobuf_local *local_nb, *lnb;
        struct obd_ioobj *ioo;
        struct ost_body *body;
        int cmd, rc, i, j, objcount, niocount, size[2] = {sizeof(*body)};
        void *tmp1, *tmp2, *end2;
        void *desc_priv = NULL;
        int reply_sent = 0;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        end2 = (char *)tmp2 + req->rq_reqmsg->buflens[2];
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        niocount = req->rq_reqmsg->buflens[2] / sizeof(*remote_nb);
        cmd = OBD_BRW_WRITE;

        for (i = 0; i < objcount; i++) {
                ost_unpack_ioo((void *)&tmp1, &ioo);
                if (tmp2 + ioo->ioo_bufcnt > end2) {
                        rc = -EFAULT;
                        break;
                }
                for (j = 0; j < ioo->ioo_bufcnt; j++)
                        ost_unpack_niobuf((void *)&tmp2, &remote_nb);
        }

        size[1] = niocount * sizeof(*remote_nb);
        rc = lustre_pack_msg(2, size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                GOTO(out, rc);
        remote_nb = lustre_msg_buf(req->rq_repmsg, 1);

        OBD_ALLOC(local_nb, niocount * sizeof(*local_nb));
        if (local_nb == NULL)
                GOTO(out, rc = -ENOMEM);

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        req->rq_status = obd_preprw(cmd, conn, objcount,
                                    tmp1, niocount, tmp2, local_nb, &desc_priv);
        if (req->rq_status)
                GOTO(out_free, rc = 0); /* XXX is this correct? */

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(fail_preprw, rc = -ENOMEM);
        desc->b_cb = NULL;
        desc->b_portal = OSC_BULK_PORTAL;
        desc->b_desc_private = desc_priv;
        memcpy(&(desc->b_conn), &conn, sizeof(conn));

        for (i = 0, lnb = local_nb; i < niocount; i++, lnb++) {
                struct ptlrpc_service *srv = req->rq_obd->u.ost.ost_service;
                struct ptlrpc_bulk_page *bulk;

                bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(fail_bulk, rc = -ENOMEM);

                spin_lock(&srv->srv_lock);
                bulk->b_xid = srv->srv_xid++;
                spin_unlock(&srv->srv_lock);

                bulk->b_buf = lnb->addr;
                bulk->b_page = lnb->page;
                bulk->b_flags = lnb->flags;
                bulk->b_dentry = lnb->dentry;
                bulk->b_buflen = PAGE_SIZE;
                bulk->b_cb = NULL;

                /* this advances remote_nb */
                ost_pack_niobuf((void **)&remote_nb, lnb->offset, lnb->len, 0,
                                bulk->b_xid);
        }

        rc = ptlrpc_register_bulk(desc);
        if (rc)
                GOTO(fail_bulk, rc);

        reply_sent = 1;
        ptlrpc_reply(req->rq_svc, req);

#warning OST must time out here.
        wait_event(desc->b_waitq, desc->b_flags & PTL_BULK_FL_RCVD);

        rc = obd_commitrw(cmd, conn, objcount, tmp1, niocount, local_nb,
                          desc->b_desc_private);
        ptlrpc_free_bulk(desc);
        EXIT;
out_free:
        OBD_FREE(local_nb, niocount * sizeof(*local_nb));
out:
        if (!reply_sent) {
                if (rc)
                        ptlrpc_error(req->rq_svc, req);
                else
                        ptlrpc_reply(req->rq_svc, req);
        }
        return rc;

fail_bulk:
        ptlrpc_free_bulk(desc);
fail_preprw:
        /* FIXME: how do we undo the preprw? */
        goto out_free;
}

static int ost_handle(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_OST_HANDLE_UNPACK)) {
                CERROR("lustre_ost: Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->type != PTL_RPC_MSG_REQUEST) {
                CERROR("lustre_ost: wrong packet type sent %d\n",
                       req->rq_reqmsg->type);
                GOTO(out, rc = -EINVAL);
        }

        if (req->rq_reqmsg->opc != OST_CONNECT &&
            req->rq_export == NULL) {
                CERROR("lustre_ost: operation %d on unconnected OST\n",
                       req->rq_reqmsg->opc);
                GOTO(out, rc = -ENOTCONN);
        }

        if (strcmp(req->rq_obd->obd_type->typ_name, "ost") != 0)
                GOTO(out, rc = -EINVAL);

        switch (req->rq_reqmsg->opc) {
        case OST_CONNECT:
                CDEBUG(D_INODE, "connect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CONNECT_NET, 0);
                rc = target_handle_connect(req);
                break;
        case OST_DISCONNECT:
                CDEBUG(D_INODE, "disconnect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                break;
        case OST_CREATE:
                CDEBUG(D_INODE, "create\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CREATE_NET, 0);
                rc = ost_create(req);
                break;
        case OST_DESTROY:
                CDEBUG(D_INODE, "destroy\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DESTROY_NET, 0);
                rc = ost_destroy(req);
                break;
        case OST_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_GETATTR_NET, 0);
                rc = ost_getattr(req);
                break;
        case OST_SETATTR:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_SETATTR_NET, 0);
                rc = ost_setattr(req);
                break;
        case OST_OPEN:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_OPEN_NET, 0);
                rc = ost_open(req);
                break;
        case OST_CLOSE:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CLOSE_NET, 0);
                rc = ost_close(req);
                break;
        case OST_WRITE:
                CDEBUG(D_INODE, "write\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw_write(req);
                /* ost_brw sends its own replies */
                RETURN(rc);
        case OST_READ:
                CDEBUG(D_INODE, "read\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw_read(req);
                /* ost_brw sends its own replies */
                RETURN(rc);
        case OST_PUNCH:
                CDEBUG(D_INODE, "punch\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_PUNCH_NET, 0);
                rc = ost_punch(req);
                break;
        case OST_STATFS:
                CDEBUG(D_INODE, "statfs\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_STATFS_NET, 0);
                rc = ost_statfs(req);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req->rq_svc, req);
                RETURN(rc);
        }

        EXIT;
out:
        //req->rq_status = rc;
        if (rc) {
                CERROR("ost: processing error (opcode=%d): %d\n",
                       req->rq_reqmsg->opc, rc);
                ptlrpc_error(req->rq_svc, req);
        } else {
                CDEBUG(D_INODE, "sending reply\n");
                if (req->rq_repmsg == NULL)
                        CERROR("handler for opcode %d returned rc=0 without "
                               "creating rq_repmsg; needs to return rc != "
                               "0!\n", req->rq_reqmsg->opc);
                ptlrpc_reply(req->rq_svc, req);
        }

        return 0;
}

#define OST_NUM_THREADS 6

/* mount the file system (secretly) */
static int ost_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct ost_obd *ost = &obddev->u.ost;
        struct obd_device *tgt;
        int err;
        int i;
        ENTRY;

        if (data->ioc_dev < 0 || data->ioc_dev > MAX_OBD_DEVICES)
                RETURN(-ENODEV);

        MOD_INC_USE_COUNT;
        tgt = &obd_dev[data->ioc_dev];
        if (!(tgt->obd_flags & OBD_ATTACHED) ||
            !(tgt->obd_flags & OBD_SET_UP)) {
                CERROR("device not attached or not set up (%d)\n",
                       data->ioc_dev);
                GOTO(error_dec, err = -EINVAL);
        }

        err = obd_connect(&ost->ost_conn, tgt);
        if (err) {
                CERROR("fail to connect to device %d\n", data->ioc_dev);
                GOTO(error_dec, err = -EINVAL);
        }

        ost->ost_service = ptlrpc_init_svc(64 * 1024, OST_REQUEST_PORTAL,
                                           OSC_REPLY_PORTAL, "self",ost_handle);
        if (!ost->ost_service) {
                CERROR("failed to start service\n");
                GOTO(error_disc, err = -EINVAL);
        }

        for (i = 0; i < OST_NUM_THREADS; i++) {
                err = ptlrpc_start_thread(obddev, ost->ost_service,
                                          "lustre_ost");
                if (err) {
                        CERROR("error starting thread #%d: rc %d\n", i, err);
                        GOTO(error_disc, err = -EINVAL);
                }
        }

        RETURN(0);

error_disc:
        obd_disconnect(&ost->ost_conn);
error_dec:
        MOD_DEC_USE_COUNT;
        RETURN(err);
}

static int ost_cleanup(struct obd_device * obddev)
{
        struct ost_obd *ost = &obddev->u.ost;
        int err;

        ENTRY;

        if ( !list_empty(&obddev->obd_exports) ) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        ptlrpc_stop_all_threads(ost->ost_service);
        ptlrpc_unregister_service(ost->ost_service);

        err = obd_disconnect(&ost->ost_conn);
        if (err) {
                CERROR("lustre ost: fail to disconnect device\n");
                RETURN(-EINVAL);
        }

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops ost_obd_ops = {
        o_setup:       ost_setup,
        o_cleanup:     ost_cleanup,
};

static int __init ost_init(void)
{
        class_register_type(&ost_obd_ops, LUSTRE_OST_NAME);
        return 0;
}

static void __exit ost_exit(void)
{
        class_unregister_type(LUSTRE_OST_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
