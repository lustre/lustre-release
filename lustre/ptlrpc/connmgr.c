/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  obd/rpc/recovd.c
 *
 *  Lustre High Availability Daemon
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com>
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_RPC

#include <linux/kmod.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>

static int connmgr_unpack_body(struct ptlrpc_request *req)
{
        struct connmgr_body *b = lustre_msg_buf(req->rq_repmsg, 0);
        if (b == NULL) {
                LBUG();
                RETURN(-EINVAL);
        }

        b->generation = NTOH__u32(b->generation);

        return 0;
}

int connmgr_connect(struct recovd_obd *recovd, struct ptlrpc_connection *conn)
{
        struct ptlrpc_request *req;
        struct ptlrpc_client *cl;
        struct connmgr_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!recovd) {
                CERROR("no manager\n");
                LBUG();
        }
        cl = recovd->recovd_client;

        req = ptlrpc_prep_req(cl, conn, CONNMGR_CONNECT, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        body->generation = HTON__u32(conn->c_generation);
        body->conn = (__u64)(unsigned long)conn;
        body->conn_token = conn->c_token;
        strncpy(body->conn_uuid, conn->c_local_uuid, sizeof(body->conn_uuid));

        req->rq_replen = lustre_msg_size(1, &size);
        req->rq_level = LUSTRE_CONN_NEW;

        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);
        if (!rc) {
                rc = connmgr_unpack_body(req);
                if (rc)
                        GOTO(out_free, rc);
                body = lustre_msg_buf(req->rq_repmsg, 0);
                CDEBUG(D_NET, "remote generation: %o\n", body->generation);
                conn->c_level = LUSTRE_CONN_CON;
                conn->c_remote_conn = body->conn;
                conn->c_remote_token = body->conn_token;
                strncpy(conn->c_remote_uuid, body->conn_uuid,
                        sizeof(conn->c_remote_uuid));
        }

        EXIT;
 out_free:
        ptlrpc_free_req(req);
 out:
        return rc;
}

static int connmgr_handle_connect(struct ptlrpc_request *req)
{
        struct connmgr_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        rc = lustre_pack_msg(1, &size, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc) {
                CERROR("connmgr: out of memory\n");
                req->rq_status = -ENOMEM;
                RETURN(0);
        }

        body = lustre_msg_buf(req->rq_reqmsg, 0);
        connmgr_unpack_body(req);

        req->rq_connection->c_remote_conn = body->conn;
        req->rq_connection->c_remote_token = body->conn_token;
        strncpy(req->rq_connection->c_remote_uuid, body->conn_uuid,
                sizeof(req->rq_connection->c_remote_uuid));

        CERROR("incoming generation %d\n", body->generation);
        body = lustre_msg_buf(req->rq_repmsg, 0);
        body->generation = 4711;
        body->conn = (__u64)(unsigned long)req->rq_connection;
        body->conn_token = req->rq_connection->c_token;

        req->rq_connection->c_level = LUSTRE_CONN_CON;
        RETURN(0);
}

int connmgr_handle(struct obd_device *dev, struct ptlrpc_service *svc,
                   struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        rc = lustre_unpack_msg(req->rq_reqmsg, req->rq_reqlen);
        if (rc) {
                CERROR("Invalid request\n");
                GOTO(out, rc);
        }

        if (req->rq_reqmsg->type != NTOH__u32(PTL_RPC_MSG_REQUEST)) {
                CERROR("wrong packet type sent %d\n",
                       req->rq_reqmsg->type);
                GOTO(out, rc = -EINVAL);
        }

        switch (req->rq_reqmsg->opc) {
        case CONNMGR_CONNECT:
                CDEBUG(D_INODE, "connmgr connect\n");
                rc = connmgr_handle_connect(req);
                break;

        default:
                rc = ptlrpc_error(svc, req);
                RETURN(rc);
        }

        EXIT;
out:
        if (rc) {
                ptlrpc_error(svc, req);
        } else {
                CDEBUG(D_NET, "sending reply\n");
                ptlrpc_reply(svc, req);
        }

        return 0;
}
