/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 */

#define EXPORT_SYMTAB

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/lustre_net.h>

void llite_ha_conn_manage(struct lustre_ha_mgr *mgr, struct ptlrpc_client *cli)
{
        ENTRY;
        cli->cli_ha_mgr = mgr;
        spin_lock(&mgr->mgr_lock);
        list_add(&cli->cli_ha_item, &mgr->mgr_connections_lh); 
        spin_unlock(&mgr->mgr_lock); 
        EXIT;
}

void llite_ha_conn_fail(struct ptlrpc_client *cli)
{
        ENTRY;
        spin_lock(&cli->cli_ha_mgr->mgr_lock);
        list_del(&cli->cli_ha_item);
        list_add(&cli->cli_ha_item, &cli->cli_ha_mgr->mgr_troubled_lh); 
        spin_unlock(&cli->cli_ha_mgr->mgr_lock); 
        wake_up(&cli->cli_ha_mgr->mgr_waitq);
        EXIT;
}

void ptlrpc_init_client(struct lustre_ha_mgr *mgr, int req_portal,
                        int rep_portal, struct ptlrpc_client *cl)
{
        memset(cl, 0, sizeof(*cl));
        cl->cli_ha_mgr = mgr;
        if (mgr)
                llite_ha_conn_manage(mgr, cl);
        cl->cli_obd = NULL;
        cl->cli_request_portal = req_portal;
        cl->cli_reply_portal = rep_portal;
        INIT_LIST_HEAD(&cl->cli_sending_head);
        INIT_LIST_HEAD(&cl->cli_sent_head);
        sema_init(&cl->cli_rpc_sem, 32);
}

struct ptlrpc_connection *ptlrpc_connect_client(char *uuid)
{
        struct ptlrpc_connection *c;
        struct lustre_peer peer;
        int err;

        err = kportal_uuid_to_peer(uuid, &peer);
        if (err != 0) {
                CERROR("cannot find peer %s!\n", uuid);
                return NULL;
        }

        c = ptlrpc_get_connection(&peer);
        if (c)
                c->c_epoch++;

        return c;
}

struct ptlrpc_bulk_desc *ptlrpc_prep_bulk(struct ptlrpc_connection *conn)
{
        struct ptlrpc_bulk_desc *bulk;

        OBD_ALLOC(bulk, sizeof(*bulk));
        if (bulk != NULL) {
                bulk->b_connection = ptlrpc_connection_addref(conn);
                init_waitqueue_head(&bulk->b_waitq);
        }

        return bulk;
}

struct ptlrpc_request *ptlrpc_prep_req(struct ptlrpc_client *cl,
                                       struct ptlrpc_connection *conn,
                                       int opcode, int count, int *lengths,
                                       char **bufs)
{
        struct ptlrpc_request *request;
        int rc;
        ENTRY;

        OBD_ALLOC(request, sizeof(*request));
        if (!request) {
                CERROR("request allocation out of memory\n");
                RETURN(NULL);
        }

        rc = lustre_pack_msg(count, lengths, bufs,
                             &request->rq_reqlen, &request->rq_reqmsg);
        if (rc) {
                CERROR("cannot pack request %d\n", rc);
                RETURN(NULL);
        }

        request->rq_time = CURRENT_TIME;
        request->rq_type = PTL_RPC_REQUEST;
        request->rq_connection = ptlrpc_connection_addref(conn);

        request->rq_reqmsg->conn = (__u64)(unsigned long)conn->c_remote_conn;
        request->rq_reqmsg->token = conn->c_remote_token;
        request->rq_reqmsg->opc = HTON__u32(opcode);
        request->rq_reqmsg->type = HTON__u32(request->rq_type);

        spin_lock(&conn->c_lock);
        request->rq_reqmsg->xid = HTON__u32(++conn->c_xid_out);
        spin_unlock(&conn->c_lock);

        request->rq_client = cl;

        RETURN(request);
}

void ptlrpc_free_req(struct ptlrpc_request *request)
{
        if (request == NULL)
                return;

        if (request->rq_repmsg != NULL)
                OBD_FREE(request->rq_repmsg, request->rq_replen);

        ptlrpc_put_connection(request->rq_connection);

        OBD_FREE(request, sizeof(*request));
}

static int ptlrpc_check_reply(struct ptlrpc_request *req)
{
        int rc = 0;

        schedule_timeout(3 * HZ);  /* 3 second timeout */
        if (req->rq_repmsg != NULL) {
                req->rq_flags = PTL_RPC_REPLY;
                GOTO(out, rc = 1);
        }

        if (CURRENT_TIME - req->rq_time >= 3) { 
                CERROR("-- REQ TIMEOUT --\n"); 
                if (req->rq_client && req->rq_client->cli_ha_mgr)
                        llite_ha_conn_fail(req->rq_client); 
                return 0;
        }

        if (sigismember(&(current->pending.signal), SIGKILL) ||
            sigismember(&(current->pending.signal), SIGTERM) ||
            sigismember(&(current->pending.signal), SIGINT)) {
                req->rq_flags = PTL_RPC_INTR;
                GOTO(out, rc = 1);
        }

 out:
        return rc;
}

int ptlrpc_check_status(struct ptlrpc_request *req, int err)
{
        ENTRY;

        if (err != 0) {
                CERROR("err is %d\n", err);
                RETURN(err);
        }

        if (req == NULL) {
                CERROR("req == NULL\n");
                RETURN(-ENOMEM);
        }

        if (req->rq_repmsg == NULL) {
                CERROR("req->rq_repmsg == NULL\n");
                RETURN(-ENOMEM);
        }

        if (req->rq_repmsg->status != 0) {
                CERROR("req->rq_repmsg->status is %d\n",
                       req->rq_repmsg->status);
                /* XXX: translate this error from net to host */
                RETURN(req->rq_repmsg->status);
        }

        RETURN(0);
}

static void ptlrpc_cleanup_request_buf(struct ptlrpc_request *request)
{
        OBD_FREE(request->rq_reqmsg, request->rq_reqlen);
        request->rq_reqmsg = NULL;
        request->rq_reqlen = 0;
}

/* Abort this request and cleanup any resources associated with it. */
static int ptlrpc_abort(struct ptlrpc_request *request)
{
        /* First remove the ME for the reply; in theory, this means
         * that we can tear down the buffer safely. */
        PtlMEUnlink(request->rq_reply_me_h);
        OBD_FREE(request->rq_reply_md.start, request->rq_replen);
        request->rq_repmsg = NULL;
        request->rq_replen = 0;
        return 0;
}

int ptlrpc_queue_wait(struct ptlrpc_request *req)
{
        int rc = 0;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);

        rc = ptl_send_rpc(req);
        if (rc) {
                CERROR("error %d, opcode %d\n", rc, req->rq_reqmsg->opc);
                ptlrpc_cleanup_request_buf(req);
                up(&req->rq_client->cli_rpc_sem);
                RETURN(-rc);
        }

        CDEBUG(D_OTHER, "-- sleeping\n");
        wait_event_interruptible(req->rq_wait_for_rep, ptlrpc_check_reply(req));
        CDEBUG(D_OTHER, "-- done\n");
        ptlrpc_cleanup_request_buf(req);
        up(&req->rq_client->cli_rpc_sem);
        if (req->rq_flags == PTL_RPC_INTR) {
                /* Clean up the dangling reply buffers */
                ptlrpc_abort(req);
                GOTO(out, rc = -EINTR);
        }

        if (req->rq_flags != PTL_RPC_REPLY) {
                CERROR("Unknown reason for wakeup\n");
                /* XXX Phil - I end up here when I kill obdctl */
                ptlrpc_abort(req);
                GOTO(out, rc = -EINTR);
        }

        rc = lustre_unpack_msg(req->rq_repmsg, req->rq_replen);
        if (rc) {
                CERROR("unpack_rep failed: %d\n", rc);
                GOTO(out, rc);
        }
        CDEBUG(D_NET, "got rep %d\n", req->rq_repmsg->xid);

        if (req->rq_repmsg->status == 0)
                CDEBUG(D_NET, "--> buf %p len %d status %d\n", req->rq_repmsg,
                       req->rq_replen, req->rq_repmsg->status);

        EXIT;
 out:
        return rc;
}
