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

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/lustre_ha.h>

void ptlrpc_init_client(struct recovd_obd *recovd, 
                        int (*recover)(struct ptlrpc_client *recover),
                        int req_portal,
                        int rep_portal, struct ptlrpc_client *cl)
{
        memset(cl, 0, sizeof(*cl));
        cl->cli_recovd = recovd;
        cl->cli_recover = recover;
        if (recovd)
                recovd_cli_manage(recovd, cl);
        cl->cli_obd = NULL;
        cl->cli_request_portal = req_portal;
        cl->cli_reply_portal = rep_portal;
        INIT_LIST_HEAD(&cl->cli_delayed_head);
        INIT_LIST_HEAD(&cl->cli_sending_head);
        INIT_LIST_HEAD(&cl->cli_dying_head);
        spin_lock_init(&cl->cli_lock);
        sema_init(&cl->cli_rpc_sem, 32);
}

__u8 *ptlrpc_req_to_uuid(struct ptlrpc_request *req)
{
        return req->rq_connection->c_remote_uuid;
}

struct ptlrpc_connection *ptlrpc_uuid_to_connection(char *uuid)
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
        if (c) { 
                memcpy(c->c_remote_uuid, uuid, sizeof(c->c_remote_uuid));
                c->c_epoch++;
        }

        return c;
}

void ptlrpc_readdress_connection(struct ptlrpc_connection *conn, char *uuid)
{
        struct lustre_peer peer;
        int err;

        err = kportal_uuid_to_peer(uuid, &peer);
        if (err != 0) {
                CERROR("cannot find peer %s!\n", uuid);
                return;
        }
        
        memcpy(&conn->c_peer, &peer, sizeof(peer)); 
        return;
}

struct ptlrpc_bulk_desc *ptlrpc_prep_bulk(struct ptlrpc_connection *conn)
{
        struct ptlrpc_bulk_desc *bulk;

        OBD_ALLOC(bulk, sizeof(*bulk));
        if (bulk != NULL) {
                bulk->b_connection = ptlrpc_connection_addref(conn);
                atomic_set(&bulk->b_pages_remaining, 0);
                init_waitqueue_head(&bulk->b_waitq);
                INIT_LIST_HEAD(&bulk->b_page_list);
        }

        return bulk;
}

struct ptlrpc_bulk_page *ptlrpc_prep_bulk_page(struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_bulk_page *bulk;

        OBD_ALLOC(bulk, sizeof(*bulk));
        if (bulk != NULL) {
                bulk->b_desc = desc;
                ptl_set_inv_handle(&bulk->b_md_h);
                ptl_set_inv_handle(&bulk->b_me_h);
                list_add_tail(&bulk->b_link, &desc->b_page_list);
                desc->b_page_count++;
                atomic_inc(&desc->b_pages_remaining);
        }
        return bulk;
}

void ptlrpc_free_bulk(struct ptlrpc_bulk_desc *desc)
{
        struct list_head *tmp, *next;
        ENTRY;
        if (desc == NULL) {
                EXIT;
                return;
        }

        list_for_each_safe(tmp, next, &desc->b_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, b_link);
                ptlrpc_free_bulk_page(bulk);
        }

        ptlrpc_put_connection(desc->b_connection);

        OBD_FREE(desc, sizeof(*desc));
        EXIT;
}

void ptlrpc_free_bulk_page(struct ptlrpc_bulk_page *bulk)
{
        ENTRY;
        if (bulk == NULL) {
                EXIT;
                return;
        }

        list_del(&bulk->b_link);
        bulk->b_desc->b_page_count--;
        OBD_FREE(bulk, sizeof(*bulk));
        EXIT;
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
                OBD_FREE(request, sizeof(*request));
                RETURN(NULL);
        }

        request->rq_type = PTL_RPC_TYPE_REQUEST;
        request->rq_connection = ptlrpc_connection_addref(conn);

        request->rq_reqmsg->opc = HTON__u32(opcode);
        request->rq_reqmsg->type = HTON__u32(PTL_RPC_MSG_REQUEST);

        INIT_LIST_HEAD(&request->rq_list);
        INIT_LIST_HEAD(&request->rq_multi);

        /* this will be dec()d once in req_finished, once in free_committed */
        atomic_set(&request->rq_refcount, 2);

        spin_lock(&conn->c_lock);
        request->rq_xid = HTON__u32(++conn->c_xid_out);
        request->rq_xid = conn->c_xid_out;
        spin_unlock(&conn->c_lock);

        request->rq_client = cl;

        RETURN(request);
}
struct ptlrpc_request *ptlrpc_prep_req2(struct ptlrpc_client *cl,
                                        struct ptlrpc_connection *conn,
                                        struct lustre_handle *handle, 
                                       int opcode, int count, int *lengths,
                                       char **bufs)
{
        struct ptlrpc_request *req;
        req = ptlrpc_prep_req(cl, conn, opcode, count, lengths, bufs);
        ptlrpc_hdl2req(req, handle);
        return req;
}

void ptlrpc_req_finished(struct ptlrpc_request *request)
{
        if (request == NULL)
                return;

        if (request->rq_repmsg != NULL) { 
                OBD_FREE(request->rq_repmsg, request->rq_replen);
                request->rq_repmsg = NULL;
                request->rq_reply_md.start = NULL; 
        }

        if (atomic_dec_and_test(&request->rq_refcount))
                ptlrpc_free_req(request);
}

void ptlrpc_free_req(struct ptlrpc_request *request)
{
        ENTRY;
        if (request == NULL) {
                EXIT;
                return;
        }

        if (request->rq_repmsg != NULL)
                OBD_FREE(request->rq_repmsg, request->rq_replen);
        if (request->rq_reqmsg != NULL)
                OBD_FREE(request->rq_reqmsg, request->rq_reqlen);

        if (request->rq_client) {
                spin_lock(&request->rq_client->cli_lock);
                list_del_init(&request->rq_list);
                spin_unlock(&request->rq_client->cli_lock);
        }

        ptlrpc_put_connection(request->rq_connection);
        list_del(&request->rq_multi);
        OBD_FREE(request, sizeof(*request));
        EXIT;
}

static int ptlrpc_check_reply(struct ptlrpc_request *req)
{
        int rc = 0;

        if (req->rq_repmsg != NULL) {
                req->rq_transno = NTOH__u64(req->rq_repmsg->transno);
                req->rq_flags |= PTL_RPC_FL_REPLIED;
                GOTO(out, rc = 1);
        }

        if (req->rq_flags & PTL_RPC_FL_RESEND) { 
                CERROR("-- RESEND --\n");
                GOTO(out, rc = 1);
        }

        if (req->rq_flags & PTL_RPC_FL_RECOVERY) { 
                CERROR("-- RESTART --\n");
                GOTO(out, rc = 1);
        }


        if (CURRENT_TIME - req->rq_time >= req->rq_timeout) {
                CERROR("-- REQ TIMEOUT ON CONNID %d XID %Ld --\n",
                       req->rq_connid, (unsigned long long)req->rq_xid);
                /* clear the timeout */
                req->rq_timeout = 0;
                req->rq_connection->c_level = LUSTRE_CONN_RECOVD;
                req->rq_flags |= PTL_RPC_FL_TIMEOUT;
                if (req->rq_client && req->rq_client->cli_recovd)
                        recovd_cli_fail(req->rq_client);
                if (req->rq_level < LUSTRE_CONN_FULL)
                        rc = 1;
                else
                        rc = 0;
                GOTO(out, rc);
        }

        if (req->rq_timeout) { 
                schedule_timeout(req->rq_timeout * HZ);
        }

        if (sigismember(&(current->pending.signal), SIGKILL) ||
            sigismember(&(current->pending.signal), SIGTERM) ||
            sigismember(&(current->pending.signal), SIGINT)) {
                req->rq_flags |= PTL_RPC_FL_INTR;
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

        if (req->rq_repmsg->type == NTOH__u32(PTL_RPC_MSG_ERR)) {
                CERROR("req->rq_repmsg->type == PTL_RPC_MSG_ERR\n");
                RETURN(-EINVAL);
        }

        if (req->rq_repmsg->status != 0) {
                if (req->rq_repmsg->status < 0)
                        CERROR("req->rq_repmsg->status is %d\n",
                               req->rq_repmsg->status);
                else
                        CDEBUG(D_INFO, "req->rq_repmsg->status is %d\n",
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

/* caller must lock cli */
void ptlrpc_free_committed(struct ptlrpc_client *cli)
{
        struct list_head *tmp, *saved;
        struct ptlrpc_request *req;

        list_for_each_safe(tmp, saved, &cli->cli_sending_head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                if ( (req->rq_flags & PTL_RPC_FL_REPLAY) ) { 
                        CDEBUG(D_INFO, "Retaining request %Ld for replay\n",
                               req->rq_xid);
                        continue;
                }

                /* not yet committed */
                if (req->rq_transno > cli->cli_last_committed)
                        break;

                CDEBUG(D_INFO, "Marking request %Ld as committed ("
                       "transno=%Lu, last_committed=%Lu\n", 
                       req->rq_xid, req->rq_transno, 
                       cli->cli_last_committed);
                if (atomic_dec_and_test(&req->rq_refcount)) {
                        /* we do this to prevent free_req deadlock */
                        list_del_init(&req->rq_list); 
                        req->rq_client = NULL;
                        ptlrpc_free_req(req);
                } else {
                        list_del_init(&req->rq_list);
                        list_add(&req->rq_list, &cli->cli_dying_head);
                }
        }

        EXIT;
        return;
}

void ptlrpc_cleanup_client(struct ptlrpc_client *cli)
{
        struct list_head *tmp, *saved;
        struct ptlrpc_request *req;
        ENTRY;

        spin_lock(&cli->cli_lock);
        list_for_each_safe(tmp, saved, &cli->cli_sending_head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                CDEBUG(D_INFO, "Cleaning req %p from sending list.\n", req);
                list_del_init(&req->rq_list);
                req->rq_client = NULL;
                ptlrpc_free_req(req); 
        }
        list_for_each_safe(tmp, saved, &cli->cli_dying_head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                CERROR("Request %p is on the dying list at cleanup!\n", req);
                list_del_init(&req->rq_list);
                req->rq_client = NULL;
                ptlrpc_free_req(req); 
        }
        spin_unlock(&cli->cli_lock);

        EXIT;
        return;
}

void ptlrpc_continue_req(struct ptlrpc_request *req)
{
        ENTRY;
        CDEBUG(D_INODE, "continue delayed request %Ld opc %d\n", 
               req->rq_xid, req->rq_reqmsg->opc); 
        wake_up_interruptible(&req->rq_wait_for_rep); 
        EXIT;
}

void ptlrpc_resend_req(struct ptlrpc_request *req)
{
        ENTRY;
        CDEBUG(D_INODE, "resend request %Ld, opc %d\n", 
               req->rq_xid, req->rq_reqmsg->opc);
        req->rq_status = -EAGAIN;
        req->rq_level = LUSTRE_CONN_RECOVD;
        req->rq_flags |= PTL_RPC_FL_RESEND;
        req->rq_flags &= ~PTL_RPC_FL_TIMEOUT;
        wake_up_interruptible(&req->rq_wait_for_rep);
        EXIT;
}

void ptlrpc_restart_req(struct ptlrpc_request *req)
{
        ENTRY;
        CDEBUG(D_INODE, "restart completed request %Ld, opc %d\n", 
               req->rq_xid, req->rq_reqmsg->opc);
        req->rq_status = -ERESTARTSYS;
        req->rq_flags |= PTL_RPC_FL_RECOVERY;
        req->rq_flags &= ~PTL_RPC_FL_TIMEOUT;
        wake_up_interruptible(&req->rq_wait_for_rep);
        EXIT;
}

int ptlrpc_queue_wait(struct ptlrpc_request *req)
{
        int rc = 0;
        struct ptlrpc_client *cli = req->rq_client;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);
        CDEBUG(D_NET, "subsys: %s req %Ld opc %d level %d, conn level %d\n",
               cli->cli_name, req->rq_xid, req->rq_reqmsg->opc, req->rq_level,
               req->rq_connection->c_level);

        /* XXX probably both an import and connection level are needed */
        if (req->rq_level > req->rq_connection->c_level) { 
                CERROR("process %d waiting for recovery\n", current->pid);
                spin_lock(&cli->cli_lock);
                list_del_init(&req->rq_list);
                list_add(&req->rq_list, cli->cli_delayed_head.prev); 
                spin_unlock(&cli->cli_lock);
                wait_event_interruptible
                        (req->rq_wait_for_rep, 
                         req->rq_level <= req->rq_connection->c_level);
                spin_lock(&cli->cli_lock);
                list_del_init(&req->rq_list);
                spin_unlock(&cli->cli_lock);
                CERROR("process %d resumed\n", current->pid);
        }
 resend:
        req->rq_time = CURRENT_TIME;
        req->rq_timeout = 100;
        rc = ptl_send_rpc(req);
        if (rc) {
                CERROR("error %d, opcode %d\n", rc, req->rq_reqmsg->opc);
                if ( rc > 0 ) 
                        rc = -rc;
                ptlrpc_cleanup_request_buf(req);
                up(&cli->cli_rpc_sem);
                RETURN(-rc);
        }

        spin_lock(&cli->cli_lock);
        list_del_init(&req->rq_list);
        list_add_tail(&req->rq_list, &cli->cli_sending_head);
        spin_unlock(&cli->cli_lock);

        CDEBUG(D_OTHER, "-- sleeping\n");
        wait_event_interruptible(req->rq_wait_for_rep, 
                                 ptlrpc_check_reply(req));
        CDEBUG(D_OTHER, "-- done\n");

        if (req->rq_flags & PTL_RPC_FL_RESEND) {
                req->rq_flags &= ~PTL_RPC_FL_RESEND;
                goto resend;
        }

        up(&cli->cli_rpc_sem);
        if (req->rq_flags & PTL_RPC_FL_TIMEOUT)
                GOTO(out, rc = -ETIMEDOUT);

        if (req->rq_flags & PTL_RPC_FL_INTR) {
                /* Clean up the dangling reply buffers */
                ptlrpc_abort(req);
                GOTO(out, rc = -EINTR);
        }

        if (!(req->rq_flags & PTL_RPC_FL_REPLIED))
                GOTO(out, rc = req->rq_status);

        rc = lustre_unpack_msg(req->rq_repmsg, req->rq_replen);
        if (rc) {
                CERROR("unpack_rep failed: %d\n", rc);
                GOTO(out, rc);
        }
        CDEBUG(D_NET, "got rep %Ld\n", req->rq_xid);
        if (req->rq_repmsg->status == 0)
                CDEBUG(D_NET, "--> buf %p len %d status %d\n", req->rq_repmsg,
                       req->rq_replen, req->rq_repmsg->status);

        spin_lock(&cli->cli_lock);
        cli->cli_last_rcvd = req->rq_repmsg->last_rcvd;
        cli->cli_last_committed = req->rq_repmsg->last_committed;
        ptlrpc_free_committed(cli); 
        spin_unlock(&cli->cli_lock);

        EXIT;
 out:
        return rc;
}

int ptlrpc_replay_req(struct ptlrpc_request *req)
{
        int rc = 0;
        struct ptlrpc_client *cli = req->rq_client;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);
        CDEBUG(D_NET, "req %Ld opc %d level %d, conn level %d\n",
               req->rq_xid, req->rq_reqmsg->opc, req->rq_level,
               req->rq_connection->c_level);

        req->rq_time = CURRENT_TIME;
        req->rq_timeout = 100;
        rc = ptl_send_rpc(req);
        if (rc) {
                CERROR("error %d, opcode %d\n", rc, req->rq_reqmsg->opc);
                ptlrpc_cleanup_request_buf(req);
                up(&cli->cli_rpc_sem);
                RETURN(-rc);
        }

        CDEBUG(D_OTHER, "-- sleeping\n");
        wait_event_interruptible(req->rq_wait_for_rep, 
                                 ptlrpc_check_reply(req));
        CDEBUG(D_OTHER, "-- done\n");

        up(&cli->cli_rpc_sem);

        if (!(req->rq_flags & PTL_RPC_FL_REPLIED)) {
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

        CDEBUG(D_NET, "got rep %Ld\n", req->rq_xid);
        if (req->rq_repmsg->status == 0)
                CDEBUG(D_NET, "--> buf %p len %d status %d\n", req->rq_repmsg,
                       req->rq_replen, req->rq_repmsg->status);
        else {
                CERROR("recovery failed: "); 
                CERROR("req %Ld opc %d level %d, conn level %d\n", 
                       req->rq_xid, req->rq_reqmsg->opc, req->rq_level,
                       req->rq_connection->c_level);
                LBUG();
        }

 out:
        RETURN(rc);
}
