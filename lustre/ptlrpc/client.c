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

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_import.h>

void ptlrpc_init_client(int req_portal, int rep_portal, char *name, 
                        struct ptlrpc_client *cl)
{
        cl->cli_request_portal = req_portal;
        cl->cli_reply_portal   = rep_portal;
        cl->cli_name           = name;
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

        c = ptlrpc_get_connection(&peer, uuid);
        if (c) { 
                memcpy(c->c_remote_uuid, uuid, sizeof(c->c_remote_uuid));
                c->c_epoch++;
        }

        CDEBUG(D_INFO, "%s -> %p\n", uuid, c);

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
        struct ptlrpc_bulk_desc *desc;

        OBD_ALLOC(desc, sizeof(*desc));
        if (desc != NULL) {
                desc->bd_connection = ptlrpc_connection_addref(conn);
                atomic_set(&desc->bd_refcount, 1);
                init_waitqueue_head(&desc->bd_waitq);
                INIT_LIST_HEAD(&desc->bd_page_list);
                ptl_set_inv_handle(&desc->bd_md_h);
                ptl_set_inv_handle(&desc->bd_me_h);
        }

        return desc;
}

struct ptlrpc_bulk_page *ptlrpc_prep_bulk_page(struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_bulk_page *bulk;

        OBD_ALLOC(bulk, sizeof(*bulk));
        if (bulk != NULL) {
                bulk->bp_desc = desc;
                list_add_tail(&bulk->bp_link, &desc->bd_page_list);
                desc->bd_page_count++;
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

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);
                ptlrpc_free_bulk_page(bulk);
        }

        ptlrpc_put_connection(desc->bd_connection);

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

        list_del(&bulk->bp_link);
        bulk->bp_desc->bd_page_count--;
        OBD_FREE(bulk, sizeof(*bulk));
        EXIT;
}

struct ptlrpc_request *ptlrpc_prep_req(struct obd_import *imp, int opcode,
                                       int count, int *lengths, char **bufs)
{
        struct ptlrpc_connection *conn = imp->imp_connection;
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

        request->rq_level = LUSTRE_CONN_FULL;
        request->rq_type = PTL_RPC_TYPE_REQUEST;
        request->rq_import = imp;
        request->rq_connection = ptlrpc_connection_addref(conn);

        INIT_LIST_HEAD(&request->rq_list);
        INIT_LIST_HEAD(&request->rq_multi);
        /* this will be dec()d once in req_finished, once in free_committed */
        atomic_set(&request->rq_refcount, 2);

        spin_lock(&conn->c_lock);
        request->rq_xid = HTON__u32(++conn->c_xid_out);
        spin_unlock(&conn->c_lock);

        request->rq_reqmsg->magic = PTLRPC_MSG_MAGIC; 
        request->rq_reqmsg->version = PTLRPC_MSG_VERSION;
        request->rq_reqmsg->opc = HTON__u32(opcode);
        request->rq_reqmsg->type = HTON__u32(PTL_RPC_MSG_REQUEST);

        ptlrpc_hdl2req(request, &imp->imp_handle);
        RETURN(request);
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

        if (request->rq_connection) {
                spin_lock(&request->rq_connection->c_lock);
                list_del_init(&request->rq_list);
                spin_unlock(&request->rq_connection->c_lock);
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

        if (req->rq_flags & PTL_RPC_FL_RECOVERY) { 
                CERROR("-- RESTART --\n");
                GOTO(out, rc = 1);
        }

 out:
        CDEBUG(D_NET, "req = %p, rc = %d\n", req, rc);
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

        err = req->rq_repmsg->status;
        if (req->rq_repmsg->type == NTOH__u32(PTL_RPC_MSG_ERR)) {
                CERROR("req->rq_repmsg->type == PTL_RPC_MSG_ERR\n");
                RETURN(err ? err : -EINVAL);
        }

        if (err != 0) {
                if (err < 0)
                        CERROR("req->rq_repmsg->status is %d\n", err);
                else
                        CDEBUG(D_INFO, "req->rq_repmsg->status is %d\n", err);
                /* XXX: translate this error from net to host */
                RETURN(err);
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

/* caller must hold conn->c_lock */
void ptlrpc_free_committed(struct ptlrpc_connection *conn)
{
        struct list_head *tmp, *saved;
        struct ptlrpc_request *req;

restart:
        list_for_each_safe(tmp, saved, &conn->c_sending_head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                if (req->rq_flags & PTL_RPC_FL_REPLAY) {
                        CDEBUG(D_INFO, "Keeping req %p xid %Ld for replay\n",
                               req, req->rq_xid);
                        continue;
                }

                /* not yet committed */
                if (req->rq_transno > conn->c_last_committed)
                        break;

                CDEBUG(D_INFO, "Marking request %p xid %Ld as committed "
                       "transno=%Lu, last_committed=%Lu\n", req,
                       (long long)req->rq_xid, (long long)req->rq_transno,
                       (long long)conn->c_last_committed);
                if (atomic_dec_and_test(&req->rq_refcount)) {
                        req->rq_import = NULL;

                        /* We do this to prevent free_req deadlock.  Restarting
                         * after each removal is not so bad, as we are almost
                         * always deleting the first item in the list.
                         */
                        spin_unlock(&conn->c_lock);
                        ptlrpc_free_req(req);
                        spin_lock(&conn->c_lock);
                        goto restart;
                } else {
                        list_del(&req->rq_list);
                        list_add(&req->rq_list, &conn->c_dying_head);
                }
        }

        EXIT;
        return;
}

void ptlrpc_cleanup_client(struct obd_import *imp)
{
        struct list_head *tmp, *saved;
        struct ptlrpc_request *req;
        struct ptlrpc_connection *conn = imp->imp_connection;
        ENTRY;

        LASSERT(conn);

restart1:
        spin_lock(&conn->c_lock);
        list_for_each_safe(tmp, saved, &conn->c_sending_head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                if (req->rq_import != imp)
                        continue;
                CDEBUG(D_INFO, "Cleaning req %p from sending list.\n", req);
                list_del_init(&req->rq_list);
                req->rq_import = NULL;
                spin_unlock(&conn->c_lock);
                ptlrpc_free_req(req);
                goto restart1;
        }
restart2:
        list_for_each_safe(tmp, saved, &conn->c_dying_head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                if (req->rq_import != imp)
                        continue;
                CERROR("Request %p is on the dying list at cleanup!\n", req);
                list_del_init(&req->rq_list);
                req->rq_import = NULL;
                spin_unlock(&conn->c_lock);
                ptlrpc_free_req(req); 
                spin_lock(&conn->c_lock);
                goto restart2;
        }
        spin_unlock(&conn->c_lock);

        EXIT;
        return;
}

void ptlrpc_continue_req(struct ptlrpc_request *req)
{
        ENTRY;
        CDEBUG(D_INODE, "continue delayed request %Ld opc %d\n", 
               req->rq_xid, req->rq_reqmsg->opc); 
        wake_up(&req->rq_wait_for_rep); 
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
        wake_up(&req->rq_wait_for_rep);
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
        wake_up(&req->rq_wait_for_rep);
        EXIT;
}

static int expired_request(void *data)
{
        struct ptlrpc_request *req = data;
        
        ENTRY;
        CERROR("req timeout on connid %d xid %Ld\n", req->rq_connid,
               (unsigned long long)req->rq_xid);
        req->rq_timeout = 0;
        req->rq_connection->c_level = LUSTRE_CONN_RECOVD;
        req->rq_flags |= PTL_RPC_FL_TIMEOUT;
        /* Activate the recovd for this client, if there is one. */
        recovd_conn_fail(req->rq_import->imp_connection);

        /* If this request is for recovery or other primordial tasks,
         * don't go back to sleep.
         */
        if (req->rq_level < LUSTRE_CONN_FULL)
                RETURN(1);
        RETURN(0);
}

static int interrupted_request(void *data)
{
        struct ptlrpc_request *req = data;
        ENTRY;
        req->rq_flags |= PTL_RPC_FL_INTR;
        RETURN(1); /* ignored, as of this writing */
}

int ptlrpc_queue_wait(struct ptlrpc_request *req)
{
        int rc = 0;
        struct l_wait_info lwi;
        struct ptlrpc_client *cli = req->rq_import->imp_client;
        struct ptlrpc_connection *conn = req->rq_import->imp_connection;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);
        CDEBUG(D_NET, "subsys: %s req %Ld opc %d level %d, conn level %d\n",
               cli->cli_name, req->rq_xid, req->rq_reqmsg->opc, req->rq_level,
               req->rq_connection->c_level);

        /* XXX probably both an import and connection level are needed */
        if (req->rq_level > conn->c_level) { 
                CERROR("process %d waiting for recovery (%d > %d)\n", 
                       current->pid, req->rq_level, conn->c_level);

                spin_lock(&conn->c_lock);
                list_del(&req->rq_list);
                list_add_tail(&req->rq_list, &conn->c_delayed_head);
                spin_unlock(&conn->c_lock);

                lwi = LWI_INTR(NULL, NULL);
                rc = l_wait_event(req->rq_wait_for_rep,
                                  req->rq_level <= conn->c_level, &lwi);

                spin_lock(&conn->c_lock);
                list_del_init(&req->rq_list);
                spin_unlock(&conn->c_lock);

                if (rc)
                        RETURN(rc);

                CERROR("process %d resumed\n", current->pid);
        }
 resend:
        req->rq_time = CURRENT_TIME;
        req->rq_timeout = obd_timeout;
        rc = ptl_send_rpc(req);
        if (rc) {
                CERROR("error %d, opcode %d\n", rc, req->rq_reqmsg->opc);
                if ( rc > 0 ) 
                        rc = -rc;
                ptlrpc_cleanup_request_buf(req);
                // up(&cli->cli_rpc_sem);
                RETURN(-rc);
        }

        spin_lock(&conn->c_lock);
        list_del(&req->rq_list);
        list_add_tail(&req->rq_list, &conn->c_sending_head);
        spin_unlock(&conn->c_lock);

        CDEBUG(D_OTHER, "-- sleeping\n");
        lwi = LWI_TIMEOUT_INTR(req->rq_timeout * HZ, expired_request,
                               interrupted_request,req);
        l_wait_event(req->rq_wait_for_rep, ptlrpc_check_reply(req), &lwi);
        CDEBUG(D_OTHER, "-- done\n");

        /* Don't resend if we were interrupted. */
        if ((req->rq_flags & (PTL_RPC_FL_RESEND | PTL_RPC_FL_INTR)) ==
            PTL_RPC_FL_RESEND) {
                req->rq_flags &= ~PTL_RPC_FL_RESEND;
                goto resend;
        }

        // up(&cli->cli_rpc_sem);
        if (req->rq_flags & PTL_RPC_FL_INTR) {
                if (!(req->rq_flags & PTL_RPC_FL_TIMEOUT))
                        LBUG(); /* should only be interrupted if we timed out. */
                /* Clean up the dangling reply buffers */
                ptlrpc_abort(req);
                GOTO(out, rc = -EINTR);
        }

        if (req->rq_flags & PTL_RPC_FL_TIMEOUT)
                GOTO(out, rc = -ETIMEDOUT);

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

        spin_lock(&conn->c_lock);
        conn->c_last_xid = req->rq_repmsg->last_xid;
        conn->c_last_committed = req->rq_repmsg->last_committed;
        ptlrpc_free_committed(conn);
        spin_unlock(&conn->c_lock);

        EXIT;
 out:
        return rc;
}

int ptlrpc_replay_req(struct ptlrpc_request *req)
{
        int rc = 0;
        // struct ptlrpc_client *cli = req->rq_import->imp_client;
        struct l_wait_info lwi;
        ENTRY;

        init_waitqueue_head(&req->rq_wait_for_rep);
        CDEBUG(D_NET, "req %Ld opc %d level %d, conn level %d\n",
               req->rq_xid, req->rq_reqmsg->opc, req->rq_level,
               req->rq_connection->c_level);

        req->rq_time = CURRENT_TIME;
        req->rq_timeout = obd_timeout;
        rc = ptl_send_rpc(req);
        if (rc) {
                CERROR("error %d, opcode %d\n", rc, req->rq_reqmsg->opc);
                ptlrpc_cleanup_request_buf(req);
                // up(&cli->cli_rpc_sem);
                RETURN(-rc);
        }

        CDEBUG(D_OTHER, "-- sleeping\n");
        lwi = LWI_INTR(NULL, NULL);
        l_wait_event(req->rq_wait_for_rep, ptlrpc_check_reply(req), &lwi);
        CDEBUG(D_OTHER, "-- done\n");

        // up(&cli->cli_rpc_sem);

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
