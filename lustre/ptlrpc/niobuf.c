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
#include <linux/lustre_net.h>
#include <linux/lustre_lib.h>

extern ptl_handle_eq_t request_out_eq, reply_in_eq, reply_out_eq,
        bulk_source_eq, bulk_sink_eq;
static ptl_process_id_t local_id = {PTL_NID_ANY, PTL_PID_ANY};

static int ptl_send_buf(struct ptlrpc_request *request,
                        struct ptlrpc_connection *conn, int portal)
{
        int rc;
        ptl_process_id_t remote_id;
        ptl_handle_md_t md_h;
        ptl_ack_req_t ack;

        request->rq_req_md.user_ptr = request;

        switch (request->rq_type) {
        case PTL_RPC_TYPE_REQUEST:
                request->rq_req_md.start = request->rq_reqmsg;
                request->rq_req_md.length = request->rq_reqlen;
                request->rq_req_md.eventq = request_out_eq;
                request->rq_req_md.threshold = 1;
                ack = PTL_NOACK_REQ;
                break;
        case PTL_RPC_TYPE_REPLY:
                request->rq_req_md.start = request->rq_repmsg;
                request->rq_req_md.length = request->rq_replen;
                request->rq_req_md.eventq = reply_out_eq;
                request->rq_req_md.threshold = 1;
                ack = PTL_NOACK_REQ;
                break;
        default:
                LBUG();
                return -1; /* notreached */
        }
        request->rq_req_md.options = PTL_MD_OP_PUT;
        request->rq_req_md.user_ptr = request;

        rc = PtlMDBind(conn->c_peer.peer_ni, request->rq_req_md, &md_h);
        //CERROR("MDBind (outgoing req/rep/bulk): %Lu\n", (__u64)md_h);
        if (rc != 0) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LBUG();
                return rc;
        }

        remote_id.nid = conn->c_peer.peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %d bytes to portal %d, xid %Ld\n",
               request->rq_req_md.length, portal, request->rq_xid);

        rc = PtlPut(md_h, ack, remote_id, portal, 0, request->rq_xid,
                    0, 0);
        if (rc != PTL_OK) {
                CERROR("PtlPut(%Lu, %d, %Ld) failed: %d\n", remote_id.nid,
                       portal, request->rq_xid, rc);
                PtlMDUnlink(md_h);
        }

        return rc;
}

static inline struct iovec *
ptlrpc_get_bulk_iov (struct ptlrpc_bulk_desc *desc)
{
        struct iovec *iov;
        
        if (desc->bd_page_count <= sizeof (desc->bd_iov)/sizeof (struct iovec))
                return (desc->bd_iov);
        
        OBD_ALLOC (iov, desc->bd_page_count * sizeof (struct iovec));
        if (iov == NULL)
                LBUG();
        
        return (iov);
}

static inline void
ptlrpc_put_bulk_iov (struct ptlrpc_bulk_desc *desc, struct iovec *iov)
{
        if (desc->bd_page_count <= sizeof (desc->bd_iov)/sizeof (struct iovec))
                return;

        OBD_FREE (iov, desc->bd_page_count * sizeof (struct iovec));
}

int ptlrpc_send_bulk(struct ptlrpc_bulk_desc *desc)
{
        int rc;
        struct list_head *tmp, *next;
        ptl_process_id_t remote_id;
        __u32 xid = 0;
        struct iovec *iov;
        ENTRY;

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                RETURN (-ENOMEM);

        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.eventq = bulk_source_eq;
        desc->bd_md.threshold = 2; /* SENT and ACK */
        desc->bd_md.options = PTL_MD_OP_PUT | PTL_MD_IOV;
        desc->bd_md.user_ptr = desc;

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT (desc->bd_md.niov < desc->bd_page_count);

                if (desc->bd_md.niov == 0)
                        xid = bulk->bp_xid;
                LASSERT (xid == bulk->bp_xid);   /* should all be the same */
                
                iov[desc->bd_md.niov].iov_base = bulk->bp_buf;
                iov[desc->bd_md.niov].iov_len = bulk->bp_buflen;
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }
        
        LASSERT (desc->bd_md.niov == desc->bd_page_count);
        LASSERT (desc->bd_md.niov != 0);
        
        rc = PtlMDBind(desc->bd_connection->c_peer.peer_ni, desc->bd_md,
                       &desc->bd_md_h);

        ptlrpc_put_bulk_iov (desc, iov);        /* move down to reduce latency to send */

        if (rc != PTL_OK) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LBUG();
                RETURN(rc);
        }
        
        remote_id.nid = desc->bd_connection->c_peer.peer_nid;
        remote_id.pid = 0;
        
        CDEBUG(D_NET, "Sending %u pages %u bytes to portal %d nid %Lx pid %d xid %d\n",
               desc->bd_md.niov, desc->bd_md.length, 
               desc->bd_portal, remote_id.nid, remote_id.pid, xid);
        
        rc = PtlPut(desc->bd_md_h, PTL_ACK_REQ, remote_id,
                    desc->bd_portal, 0, xid, 0, 0);
        if (rc != PTL_OK) {
                CERROR("PtlPut(%Lu, %d, %d) failed: %d\n",
                       remote_id.nid, desc->bd_portal, xid, rc);
                PtlMDUnlink(desc->bd_md_h);
                LBUG();
                RETURN(rc);
        }

        RETURN(0);
}

int ptlrpc_register_bulk(struct ptlrpc_bulk_desc *desc)
{
        struct list_head *tmp, *next;
        int rc;
        __u32 xid = 0;
        struct iovec *iov;
        ENTRY;

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                return (-ENOMEM);

        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.threshold = 1;
        desc->bd_md.options = PTL_MD_OP_PUT | PTL_MD_IOV;
        desc->bd_md.user_ptr = desc;
        desc->bd_md.eventq = bulk_sink_eq;

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT (desc->bd_md.niov < desc->bd_page_count);

                if (desc->bd_md.niov == 0)
                        xid = bulk->bp_xid;
                LASSERT (xid == bulk->bp_xid);   /* should all be the same */
                
                iov[desc->bd_md.niov].iov_base = bulk->bp_buf;
                iov[desc->bd_md.niov].iov_len = bulk->bp_buflen;
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }

        LASSERT (desc->bd_md.niov == desc->bd_page_count);
        LASSERT (desc->bd_md.niov != 0);
        
        rc = PtlMEAttach(desc->bd_connection->c_peer.peer_ni,
                         desc->bd_portal, local_id, xid, 0,
                         PTL_UNLINK, PTL_INS_AFTER, &desc->bd_me_h);

        ptlrpc_put_bulk_iov (desc, iov);

        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                LBUG();
                GOTO(cleanup, rc);
        }
        
        rc = PtlMDAttach(desc->bd_me_h, desc->bd_md, PTL_UNLINK,
                         &desc->bd_md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach failed: %d\n", rc);
                LBUG();
                GOTO(cleanup, rc);
        }
        
        CDEBUG(D_NET, "Setup bulk sink buffers: %u pages %u bytes, xid %u, "
               "portal %u\n", desc->bd_md.niov, desc->bd_md.length, 
               xid, desc->bd_portal);

        RETURN(0);

 cleanup:
        ptlrpc_abort_bulk(desc);

        return rc;
}

int ptlrpc_abort_bulk(struct ptlrpc_bulk_desc *desc)
{
        /* This should be safe: these handles are initialized to be
         * invalid in ptlrpc_prep_bulk() */
        PtlMDUnlink(desc->bd_md_h);
        PtlMEUnlink(desc->bd_me_h);

        return 0;
}

int ptlrpc_reply(struct ptlrpc_service *svc, struct ptlrpc_request *req)
{
        if (req->rq_repmsg == NULL) {
                CERROR("bad: someone called ptlrpc_reply when they meant "
                       "ptlrpc_error\n");
                return -EINVAL;
        }

        /* FIXME: we need to increment the count of handled events */
        req->rq_type = PTL_RPC_TYPE_REPLY;
        //req->rq_repmsg->conn = req->rq_connection->c_remote_conn;
        //req->rq_repmsg->token = req->rq_connection->c_remote_token;
        req->rq_repmsg->status = HTON__u32(req->rq_status);
        req->rq_repmsg->type = HTON__u32(req->rq_type);
        return ptl_send_buf(req, req->rq_connection, svc->srv_rep_portal);
}

int ptlrpc_error(struct ptlrpc_service *svc, struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        if (req->rq_repmsg) {
                CERROR("req already has repmsg\n");
                LBUG();
        }

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_repmsg->type = HTON__u32(PTL_RPC_MSG_ERR);

        rc = ptlrpc_reply(svc, req);
        RETURN(rc);
}


int ptl_send_rpc(struct ptlrpc_request *request)
{
        int rc;
        char *repbuf;

        ENTRY;

        if (NTOH__u32(request->rq_reqmsg->type) != PTL_RPC_MSG_REQUEST) {
                CERROR("wrong packet type sent %d\n",
                       NTOH__u32(request->rq_reqmsg->type));
                LBUG();
                RETURN(EINVAL);
        }
        if (request->rq_replen == 0) {
                CERROR("request->rq_replen is 0!\n");
                RETURN(EINVAL);
        }

        /* request->rq_repmsg is set only when the reply comes in, in
         * client_packet_callback() */
        if (request->rq_reply_md.start)
                OBD_FREE(request->rq_reply_md.start, request->rq_replen);

        OBD_ALLOC(repbuf, request->rq_replen);
        if (!repbuf) {
                LBUG();
                RETURN(ENOMEM);
        }

        // down(&request->rq_client->cli_rpc_sem);

        rc = PtlMEAttach(request->rq_connection->c_peer.peer_ni,
                         request->rq_import->imp_client->cli_reply_portal,
                         local_id, request->rq_xid, 0, PTL_UNLINK,
                         PTL_INS_AFTER, &request->rq_reply_me_h);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                LBUG();
                GOTO(cleanup, rc);
        }

        request->rq_type = PTL_RPC_TYPE_REQUEST;
        request->rq_reply_md.start = repbuf;
        request->rq_reply_md.length = request->rq_replen;
        request->rq_reply_md.threshold = 1;
        request->rq_reply_md.options = PTL_MD_OP_PUT;
        request->rq_reply_md.user_ptr = request;
        request->rq_reply_md.eventq = reply_in_eq;

        rc = PtlMDAttach(request->rq_reply_me_h, request->rq_reply_md,
                         PTL_UNLINK, &request->rq_reply_md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach failed: %d\n", rc);
                LBUG();
                GOTO(cleanup2, rc);
        }

        CDEBUG(D_NET, "Setup reply buffer: %u bytes, xid %Lu, portal %u\n",
               request->rq_replen, request->rq_xid,
               request->rq_import->imp_client->cli_reply_portal);

        rc = ptl_send_buf(request, request->rq_connection,
                          request->rq_import->imp_client->cli_request_portal);
        RETURN(rc);

 cleanup2:
        PtlMEUnlink(request->rq_reply_me_h);
 cleanup:
        OBD_FREE(repbuf, request->rq_replen);
        // up(&request->rq_client->cli_rpc_sem);

        return rc;
}

void ptlrpc_link_svc_me(struct ptlrpc_service *service, int i)
{
        int rc;
        ptl_md_t dummy;
        ptl_handle_md_t md_h;

        /* Attach the leading ME on which we build the ring */
        rc = PtlMEAttach(service->srv_self.peer_ni, service->srv_req_portal,
                         local_id, 0, ~0, PTL_RETAIN, PTL_INS_BEFORE,
                         &(service->srv_me_h[i]));
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                LBUG();
        }
        
        if (service->srv_ref_count[i])
                LBUG();

        dummy.start         = service->srv_buf[i];
        dummy.length        = service->srv_buf_size;
        dummy.max_offset    = service->srv_buf_size;
        dummy.threshold     = PTL_MD_THRESH_INF;
        dummy.options       = PTL_MD_OP_PUT | PTL_MD_AUTO_UNLINK;
        dummy.user_ptr      = service;
        dummy.eventq        = service->srv_eq_h;
        dummy.max_offset    = service->srv_buf_size;
        
        rc = PtlMDAttach(service->srv_me_h[i], dummy, PTL_UNLINK, &md_h);
        if (rc != PTL_OK) {
                /* cleanup */
                CERROR("PtlMDAttach failed: %d\n", rc);
                LBUG();
        }
}        

/* ptl_handled_rpc() should be called by the sleeping process once
 * it finishes processing an event.  This ensures the ref count is
 * decremented and that the rpc ring buffer cycles properly.
 */ 
int ptl_handled_rpc(struct ptlrpc_service *service, void *start) 
{
        int index;

        spin_lock(&service->srv_lock);
        for (index = 0; index < service->srv_ring_length; index++)
                if (service->srv_buf[index] == start) 
                        break;

        if (index == service->srv_ring_length)
                LBUG();

        CDEBUG(D_INFO, "MD index=%d Ref Count=%d\n", index,
               service->srv_ref_count[index]);
        service->srv_ref_count[index]--;

        if (service->srv_ref_count[index] < 0)
                LBUG();

        if (service->srv_ref_count[index] == 0 &&
            !ptl_is_valid_handle(&(service->srv_me_h[index]))) {
                CDEBUG(D_NET, "relinking %d\n", index); 
                ptlrpc_link_svc_me(service, index); 
        }
        
        spin_unlock(&service->srv_lock);
        return 0;
}
