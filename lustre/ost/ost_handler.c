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

static int ost_destroy(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_destroy(&conn, &body->oa);
        RETURN(0);
}

static int ost_getattr(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_getattr(&conn, &repbody->oa);
        RETURN(0);
}

static int ost_open(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_open(&conn, &repbody->oa);
        RETURN(0);
}

static int ost_close(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_close(&conn, &repbody->oa);
        RETURN(0);
}

static int ost_create(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_create(&conn, &repbody->oa);
        RETURN(0);
}

static int ost_punch(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_punch(&conn, &repbody->oa,
                                   repbody->oa.o_size, repbody->oa.o_blocks);
        RETURN(0);
}

static int ost_setattr(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body, *repbody;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        repbody = lustre_msg_buf(req->rq_repmsg, 0);
        memcpy(&repbody->oa, &body->oa, sizeof(body->oa));
        req->rq_status = obd_setattr(&conn, &repbody->oa);
        RETURN(0);
}

static int ost_connect(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_connect(&conn);

        CDEBUG(D_IOCTL, "rep buffer %p, id %d\n", req->rq_repmsg, conn.oc_id);
        body = lustre_msg_buf(req->rq_repmsg, 0);
        body->connid = conn.oc_id;
        RETURN(0);
}

static int ost_disconnect(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        CDEBUG(D_IOCTL, "Disconnecting %d\n", conn.oc_id);
        req->rq_status = obd_disconnect(&conn);
        RETURN(0);
}

static int ost_get_info(struct ost_obd *ost, struct ptlrpc_request *req)
{
        struct obd_conn conn;
        struct ost_body *body;
        int rc, size[2] = {sizeof(*body)};
        char *bufs[2] = {NULL, NULL}, *ptr;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        conn.oc_id = body->connid;
        conn.oc_dev = ost->ost_tgt;

        ptr = lustre_msg_buf(req->rq_reqmsg, 1);
        if (!ptr)
                RETURN(-EINVAL);

        req->rq_status = obd_get_info(&conn, req->rq_reqmsg->buflens[1], ptr,
                                      &(size[1]), (void **)&(bufs[1]));

        rc = lustre_pack_msg(2, size, bufs, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                CERROR("cannot pack reply\n");

        RETURN(rc);
}

static int ost_brw_read(struct ost_obd *obddev, struct ptlrpc_request *req)
{
        struct ptlrpc_bulk_desc *desc;
        struct obd_conn conn;
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
        cmd = body->data;

        conn.oc_id = body->connid;
        conn.oc_dev = req->rq_obd->u.ost.ost_tgt;

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
        req->rq_status = obd_preprw(cmd, &conn, objcount,
                                    tmp1, niocount, tmp2, local_nb);

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

        ptlrpc_free_bulk(desc);

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        req->rq_status = obd_commitrw(cmd, &conn, objcount,
                                      tmp1, niocount, local_nb);

        RETURN(rc);

 out_bulk:
        ptlrpc_free_bulk(desc);
 out_local:
        if (local_nb != NULL)
                OBD_FREE(local_nb, sizeof(*local_nb) * niocount);
 out:
        return 0;
}

static int ost_commit_page(struct obd_conn *conn, struct page *page)
{
        struct obd_ioobj obj;
        struct niobuf_local buf;
        int rc;
        ENTRY;

        memset(&buf, 0, sizeof(buf));
        memset(&obj, 0, sizeof(obj));

        buf.page = page;
        obj.ioo_bufcnt = 1;

        rc = obd_commitrw(OBD_BRW_WRITE, conn, 1, &obj, 1, &buf);
        RETURN(rc);
}

static int ost_brw_write_cb(struct ptlrpc_bulk_page *bulk)
{
        void *journal_save;
        int rc;
        ENTRY;

        /* Restore the filesystem journal context when we do the commit.
         * This is needed for ext3 and reiserfs, but can't really hurt
         * other filesystems.
         */
        journal_save = current->journal_info;
        current->journal_info = bulk->b_desc->b_journal_info;
        CDEBUG(D_BUFFS, "journal_info: saved %p->%p, restored %p\n", current,
               journal_save, bulk->b_desc->b_journal_info);
        rc = ost_commit_page(&bulk->b_desc->b_conn, bulk->b_page);
        current->journal_info = journal_save;
        CDEBUG(D_BUFFS, "journal_info: restored %p->%p\n", current,
               journal_save);
        if (rc)
                CERROR("ost_commit_page failed: %d\n", rc);

        RETURN(rc);
}

static int ost_brw_write_finished_cb(struct ptlrpc_bulk_desc *desc)
{
        ptlrpc_free_bulk(desc);

        return 0;
}

static int ost_brw_write(struct ost_obd *obddev, struct ptlrpc_request *req)
{
        struct ptlrpc_bulk_desc *desc;
        struct obd_conn conn;
        struct niobuf_remote *remote_nb;
        struct niobuf_local *local_nb, *lnb;
        struct obd_ioobj *ioo;
        struct ost_body *body;
        int cmd, rc, i, j, objcount, niocount, size[2] = {sizeof(*body)};
        void *tmp1, *tmp2, *end2;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        end2 = (char *)tmp2 + req->rq_reqmsg->buflens[2];
        objcount = req->rq_reqmsg->buflens[1] / sizeof(*ioo);
        niocount = req->rq_reqmsg->buflens[2] / sizeof(*remote_nb);
        cmd = body->data;

        conn.oc_id = body->connid;
        conn.oc_dev = req->rq_obd->u.ost.ost_tgt;

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
                GOTO(fail, rc);
        remote_nb = lustre_msg_buf(req->rq_repmsg, 1);

        OBD_ALLOC(local_nb, niocount * sizeof(*local_nb));
        if (local_nb == NULL)
                GOTO(fail, rc = -ENOMEM);

        /* The unpackers move tmp1 and tmp2, so reset them before using */
        tmp1 = lustre_msg_buf(req->rq_reqmsg, 1);
        tmp2 = lustre_msg_buf(req->rq_reqmsg, 2);
        req->rq_status = obd_preprw(cmd, &conn, objcount,
                                    tmp1, niocount, tmp2, local_nb);
        if (req->rq_status)
                GOTO(success, 0);

        desc = ptlrpc_prep_bulk(req->rq_connection);
        if (desc == NULL)
                GOTO(fail_preprw, rc = -ENOMEM);
        desc->b_cb = ost_brw_write_finished_cb;
        desc->b_portal = OSC_BULK_PORTAL;
        memcpy(&(desc->b_conn), &conn, sizeof(conn));

        /* Save journal context for commit callbacks */
        CDEBUG(D_BUFFS, "journal_info: saved %p->%p\n", current,
               current->journal_info);
        desc->b_journal_info = current->journal_info;

        for (i = 0, lnb = local_nb; i < niocount; i++, lnb++) {
                struct ptlrpc_service *srv = req->rq_obd->u.ost.ost_service;
                struct ptlrpc_bulk_page *bulk;

                bulk = ptlrpc_prep_bulk_page(desc);
                if (bulk == NULL)
                        GOTO(fail_bulk, rc = -ENOMEM);

                spin_lock(&srv->srv_lock);
                bulk->b_xid = srv->srv_xid++;
                spin_unlock(&srv->srv_lock);

                bulk->b_buf = (void *)(unsigned long)lnb->addr;
                bulk->b_page = lnb->page;
                bulk->b_buflen = PAGE_SIZE;
                bulk->b_cb = ost_brw_write_cb;

                /* this advances remote_nb */
                ost_pack_niobuf((void **)&remote_nb, lnb->offset, lnb->len, 0,
                                bulk->b_xid);
        }

        rc = ptlrpc_register_bulk(desc);
        current->journal_info = NULL; /* kind of scary */
        if (rc)
                GOTO(fail_bulk, rc);

        EXIT;
 success:
        OBD_FREE(local_nb, niocount * sizeof(*local_nb));
        return 0;

 fail_bulk:
        ptlrpc_free_bulk(desc);
 fail_preprw:
        OBD_FREE(local_nb, niocount * sizeof(*local_nb));
        /* FIXME: how do we undo the preprw? */
 fail:
        return rc;
}

static int ost_brw(struct ost_obd *obddev, struct ptlrpc_request *req)
{
        struct ost_body *body = lustre_msg_buf(req->rq_reqmsg, 0);

        if (body->data == OBD_BRW_READ)
                return ost_brw_read(obddev, req);
        else
                return ost_brw_write(obddev, req);
}

static int ost_handle(struct obd_device *obddev, struct ptlrpc_service *svc,
                      struct ptlrpc_request *req)
{
        int rc;
        struct ost_obd *ost = &obddev->u.ost;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_HANDLE_UNPACK)) {
                CERROR("lustre_mds: Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->type != PTL_RPC_MSG_REQUEST) {
                CERROR("lustre_mds: wrong packet type sent %d\n",
                       req->rq_reqmsg->type);
                GOTO(out, rc = -EINVAL);
        }

        switch (req->rq_reqmsg->opc) {
        case OST_CONNECT:
                CDEBUG(D_INODE, "connect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CONNECT_NET, 0);
                rc = ost_connect(ost, req);
                break;
        case OST_DISCONNECT:
                CDEBUG(D_INODE, "disconnect\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DISCONNECT_NET, 0);
                rc = ost_disconnect(ost, req);
                break;
        case OST_GET_INFO:
                CDEBUG(D_INODE, "get_info\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_GET_INFO_NET, 0);
                rc = ost_get_info(ost, req);
                break;
        case OST_CREATE:
                CDEBUG(D_INODE, "create\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CREATE_NET, 0);
                rc = ost_create(ost, req);
                break;
        case OST_DESTROY:
                CDEBUG(D_INODE, "destroy\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_DESTROY_NET, 0);
                rc = ost_destroy(ost, req);
                break;
        case OST_GETATTR:
                CDEBUG(D_INODE, "getattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_GETATTR_NET, 0);
                rc = ost_getattr(ost, req);
                break;
        case OST_SETATTR:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_SETATTR_NET, 0);
                rc = ost_setattr(ost, req);
                break;
        case OST_OPEN:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_OPEN_NET, 0);
                rc = ost_open(ost, req);
                break;
        case OST_CLOSE:
                CDEBUG(D_INODE, "setattr\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_CLOSE_NET, 0);
                rc = ost_close(ost, req);
                break;
        case OST_BRW:
                CDEBUG(D_INODE, "brw\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw(ost, req);
                break;
        case OST_PUNCH:
                CDEBUG(D_INODE, "punch\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_PUNCH_NET, 0);
                rc = ost_punch(ost, req);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(svc, req);
                RETURN(rc);
        }

        EXIT;
out:
        //req->rq_status = rc;
        if (rc) {
                CERROR("ost: processing error %d\n", rc);
                ptlrpc_error(svc, req);
        } else {
                CDEBUG(D_INODE, "sending reply\n");
                ptlrpc_reply(svc, req);
        }

        return 0;
}

/* mount the file system (secretly) */
static int ost_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct ost_obd *ost = &obddev->u.ost;
        struct obd_device *tgt;
        int err;
        ENTRY;

        if (data->ioc_dev < 0 || data->ioc_dev > MAX_OBD_DEVICES)
                RETURN(-ENODEV);

        MOD_INC_USE_COUNT;
        tgt = &obd_dev[data->ioc_dev];
        ost->ost_tgt = tgt;
        if (!(tgt->obd_flags & OBD_ATTACHED) ||
            !(tgt->obd_flags & OBD_SET_UP)) {
                CERROR("device not attached or not set up (%d)\n",
                       data->ioc_dev);
                GOTO(error_dec, err = -EINVAL);
        }

        ost->ost_conn.oc_dev = tgt;
        err = obd_connect(&ost->ost_conn);
        if (err) {
                CERROR("fail to connect to device %d\n", data->ioc_dev);
                GOTO(error_dec, err = -EINVAL);
        }

        ost->ost_service = ptlrpc_init_svc(128 * 1024,
                                           OST_REQUEST_PORTAL, OSC_REPLY_PORTAL,
                                           "self", ost_handle);
        if (!ost->ost_service) {
                CERROR("failed to start service\n");
                GOTO(error_disc, err = -EINVAL);
        }

        err = ptlrpc_start_thread(obddev, ost->ost_service, "lustre_ost");
        if (err)
                GOTO(error_disc, err = -EINVAL);
        err = ptlrpc_start_thread(obddev, ost->ost_service, "lustre_ost");
        if (err)
                GOTO(error_disc, err = -EINVAL);

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

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        ptlrpc_stop_all_threads(ost->ost_service);
        rpc_unregister_service(ost->ost_service);

        if (!list_empty(&ost->ost_service->srv_reqs)) {
                // XXX reply with errors and clean up
                CERROR("Request list not empty!\n");
        }
        OBD_FREE(ost->ost_service, sizeof(*ost->ost_service));

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
        obd_register_type(&ost_obd_ops, LUSTRE_OST_NAME);
        return 0;
}

static void __exit ost_exit(void)
{
        obd_unregister_type(LUSTRE_OST_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
