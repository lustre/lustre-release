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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>

extern ptl_handle_eq_t bulk_source_eq, sent_pkt_eq, rcvd_rep_eq, bulk_sink_eq;
static ptl_process_id_t local_id = {PTL_ADDR_GID, PTL_ID_ANY, PTL_ID_ANY};


int ptlrpc_check_bulk_sent(struct ptlrpc_bulk_desc *bulk)
{
        if (bulk->b_flags == PTL_BULK_SENT) {
                EXIT;
                return 1;
        }

        if (sigismember(&(current->pending.signal), SIGKILL) ||
            sigismember(&(current->pending.signal), SIGINT)) {
                bulk->b_flags = PTL_RPC_INTR;
                EXIT;
                return 1;
        }

        CDEBUG(D_NET, "no event yet\n");
        return 0;
}

int ptl_send_buf(struct ptlrpc_request *request, struct lustre_peer *peer,
                 int portal)
{
        int rc;
        ptl_process_id_t remote_id;
        ptl_handle_md_t md_h;
        ptl_ack_req_t ack;

        switch (request->rq_type) {
        case PTL_RPC_BULK:
                request->rq_req_md.start = request->rq_bulkbuf;
                request->rq_req_md.length = request->rq_bulklen;
                request->rq_req_md.eventq = bulk_source_eq;
                request->rq_req_md.threshold = 2; /* SENT and ACK events */
                ack = PTL_ACK_REQ;
                break;
        case PTL_RPC_REQUEST:
                request->rq_req_md.start = request->rq_reqbuf;
                request->rq_req_md.length = request->rq_reqlen;
                request->rq_req_md.eventq = sent_pkt_eq;
                request->rq_req_md.threshold = 1;
                ack = PTL_NOACK_REQ;
                break;
        case PTL_RPC_REPLY:
                request->rq_req_md.start = request->rq_repbuf;
                request->rq_req_md.length = request->rq_replen;
                request->rq_req_md.eventq = sent_pkt_eq;
                request->rq_req_md.threshold = 1;
                ack = PTL_NOACK_REQ;
                break;
        default:
                BUG();
                return -1; /* notreached */
        }
        request->rq_req_md.options = PTL_MD_OP_PUT;
        request->rq_req_md.user_ptr = request;

        rc = PtlMDBind(peer->peer_ni, request->rq_req_md, &md_h);
        //CERROR("MDBind (outgoing req/rep/bulk): %Lu\n", (__u64)md_h);
        if (rc != 0) {
                CERROR("PtlMDBind failed: %d\n", rc);
                BUG();
                return rc;
        }

        remote_id.addr_kind = PTL_ADDR_NID;
        remote_id.nid = peer->peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %d bytes to portal %d, xid %d\n",
               request->rq_req_md.length, portal, request->rq_xid);

        rc = PtlPut(md_h, ack, remote_id, portal, 0, request->rq_xid, 0, 0);
        if (rc != PTL_OK) {
                CERROR("PtlPut(%d, %d, %d) failed: %d\n", remote_id.nid,
                       portal, request->rq_xid, rc);
                /* FIXME: tear down md */
                BUG();
        }

        return rc;
}

int ptlrpc_send_bulk(struct ptlrpc_bulk_desc *bulk, int portal)
{
        int rc;
        ptl_process_id_t remote_id;
        ptl_handle_md_t md_h;

        bulk->b_md.start = bulk->b_buf;
        bulk->b_md.length = bulk->b_buflen;
        bulk->b_md.eventq = bulk_source_eq;
        bulk->b_md.threshold = 2; /* SENT and ACK events */
        bulk->b_md.options = PTL_MD_OP_PUT;
        bulk->b_md.user_ptr = bulk;

        rc = PtlMDBind(bulk->b_peer.peer_ni, bulk->b_md, &md_h);
        if (rc != 0) {
                CERROR("PtlMDBind failed: %d\n", rc);
                BUG();
                return rc;
        }

        remote_id.addr_kind = PTL_ADDR_NID;
        remote_id.nid = bulk->b_peer.peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %d bytes to portal %d, xid %d\n",
               bulk->b_md.length, portal, bulk->b_xid);

        rc = PtlPut(md_h, PTL_ACK_REQ, remote_id, portal, 0, bulk->b_xid, 0, 0);
        if (rc != PTL_OK) {
                CERROR("PtlPut(%d, %d, %d) failed: %d\n", remote_id.nid,
                       portal, bulk->b_xid, rc);
                PtlMDUnlink(md_h);
                BUG();
        }

        return rc;
}

int ptlrpc_register_bulk(struct ptlrpc_bulk_desc *bulk)
{
        int rc;

        ENTRY;

        rc = PtlMEPrepend(bulk->b_peer.peer_ni, bulk->b_portal, local_id,
                          bulk->b_xid, 0, PTL_UNLINK, &bulk->b_me_h);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                BUG();
                EXIT;
                goto cleanup1;
        }

        bulk->b_md.start = bulk->b_buf;
        bulk->b_md.length = bulk->b_buflen;
        bulk->b_md.threshold = 1;
        bulk->b_md.options = PTL_MD_OP_PUT;
        bulk->b_md.user_ptr = bulk;
        bulk->b_md.eventq = bulk_sink_eq;

        rc = PtlMDAttach(bulk->b_me_h, bulk->b_md, PTL_UNLINK, &bulk->b_md_h);
        //CERROR("MDAttach (bulk sink): %Lu\n", (__u64)bulk->b_md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach failed: %d\n", rc);
                BUG();
                EXIT;
                goto cleanup2;
        }

        CDEBUG(D_NET, "Setup bulk sink buffer: %u bytes, xid %u, portal %u\n",
               bulk->b_buflen, bulk->b_xid, bulk->b_portal);
        EXIT;
        return 0;

        // XXX Confirm that this is safe!
 cleanup2:
        PtlMDUnlink(bulk->b_md_h);
 cleanup1:
        PtlMEUnlink(bulk->b_me_h);
        return rc;
}

int ptlrpc_reply(struct obd_device *obddev, struct ptlrpc_service *svc,
                 struct ptlrpc_request *req)
{
	struct ptlrpc_request *clnt_req = req->rq_reply_handle;
	ENTRY;

	if (req->rq_reply_handle == NULL) {
		/* This is a request that came from the network via portals. */

		/* FIXME: we need to increment the count of handled events */
                req->rq_type = PTL_RPC_REPLY;
                req->rq_reqhdr->xid = req->rq_reqhdr->xid;
		ptl_send_buf(req, &req->rq_peer, svc->srv_rep_portal);
	} else {
		/* This is a local request that came from another thread. */

		/* move the reply to the client */ 
		clnt_req->rq_replen = req->rq_replen;
		clnt_req->rq_repbuf = req->rq_repbuf;
		req->rq_repbuf = NULL;
		req->rq_replen = 0;

		/* free the request buffer */
		OBD_FREE(req->rq_reqbuf, req->rq_reqlen);
		req->rq_reqbuf = NULL;

		/* wake up the client */ 
		wake_up_interruptible(&clnt_req->rq_wait_for_rep); 
	}

	EXIT;
	return 0;
}

int ptlrpc_error(struct obd_device *obddev, struct ptlrpc_service *svc,
                 struct ptlrpc_request *req)
{
	struct ptlrep_hdr *hdr;

	ENTRY;

	OBD_ALLOC(hdr, sizeof(*hdr));
	if (!hdr) { 
		EXIT;
		return -ENOMEM;
	}

	memset(hdr, 0, sizeof(*hdr));

	hdr->xid = req->rq_reqhdr->xid;
	hdr->status = req->rq_status; 
	hdr->type = OST_TYPE_ERR;

        if (req->rq_repbuf) { 
                CERROR("req has repbuf\n");
                BUG();
        }

	req->rq_repbuf = (char *)hdr;
	req->rq_replen = sizeof(*hdr); 

	EXIT;
	return ptlrpc_reply(obddev, svc, req);
}

int ptl_send_rpc(struct ptlrpc_request *request, struct lustre_peer *peer)
{
        ptl_process_id_t local_id;
	struct ptlreq_hdr *hdr;
        int rc;
        char *repbuf;

        ENTRY;

        hdr = (struct ptlreq_hdr *)request->rq_reqbuf;
        if (NTOH__u32(hdr->type) != OST_TYPE_REQ) {
                CERROR("lustre_ost: wrong packet type sent %d\n",
                       NTOH__u32(hdr->type));
                BUG();
        }
        if (request->rq_replen == 0) {
                CERROR("request->rq_replen is 0!\n");
                EXIT;
                return -EINVAL;
        }

        /* request->rq_repbuf is set only when the reply comes in, in
         * client_packet_callback() */
        OBD_ALLOC(repbuf, request->rq_replen);
        if (!repbuf) { 
                EXIT;
                return -ENOMEM;
        }

        local_id.addr_kind = PTL_ADDR_GID;
        local_id.gid = PTL_ID_ANY;
        local_id.rid = PTL_ID_ANY;

        //CERROR("sending req %d\n", request->rq_xid);
        rc = PtlMEPrepend(peer->peer_ni, request->rq_reply_portal, local_id,
                          request->rq_xid, 0, PTL_UNLINK,
                          &request->rq_reply_me_h);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                BUG();
                EXIT;
                goto cleanup;
        }

        request->rq_type = PTL_RPC_REQUEST;
        request->rq_reply_md.start = repbuf;
        request->rq_reply_md.length = request->rq_replen;
        request->rq_reply_md.threshold = 1;
        request->rq_reply_md.options = PTL_MD_OP_PUT;
        request->rq_reply_md.user_ptr = request;
        request->rq_reply_md.eventq = rcvd_rep_eq;

        rc = PtlMDAttach(request->rq_reply_me_h, request->rq_reply_md,
                         PTL_UNLINK, &request->rq_reply_md_h);
        //CERROR("MDAttach (send RPC): %Lu\n", (__u64)request->rq_reply_md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach failed: %d\n", rc);
                BUG();
                EXIT;
                goto cleanup2;
        }

        CDEBUG(D_NET, "Setup reply buffer: %u bytes, xid %u, portal %u\n",
               request->rq_replen, request->rq_xid, request->rq_reply_portal);

        return ptl_send_buf(request, peer, request->rq_req_portal);

 cleanup2:
        PtlMEUnlink(request->rq_reply_me_h);
 cleanup:
        OBD_FREE(repbuf, request->rq_replen);

        return rc;
}

/* ptl_handled_rpc() should be called by the sleeping process once
 * it finishes processing an event.  This ensures the ref count is
 * decremented and that the rpc ring buffer cycles properly.
 */ 
int ptl_handled_rpc(struct ptlrpc_service *service, void *start) 
{
        int rc, index = 0;

        spin_lock(&service->srv_lock);

        while (index < service->srv_ring_length) {
                if ( service->srv_md[index].start == start) 
                        break;
                index++;
        }
        if (index == service->srv_ring_length)
                BUG();

        CDEBUG(D_INFO, "MD index=%d Ref Count=%d\n", index,
               service->srv_ref_count[index]);
        service->srv_ref_count[index]--;

        if (service->srv_ref_count[index] < 0)
                BUG();
        
        if (service->srv_ref_count[index] == 0 &&
            service->srv_me_h[index] == 0) {

                /* Replace the unlinked ME and MD */
                rc = PtlMEInsert(service->srv_me_h[service->srv_me_tail],
                                 service->srv_id, 0, ~0, PTL_RETAIN,
                                 PTL_INS_AFTER, &(service->srv_me_h[index]));
                if (rc != PTL_OK) {
                        CERROR("PtlMEInsert failed: %d\n", rc);
                        BUG();
                        spin_unlock(&service->srv_lock);
                        return rc;
                }
                CDEBUG(D_NET, "Inserting new ME and MD in ring, rc %d\n", rc);

                service->srv_me_tail = index;

                service->srv_md[index].start        = service->srv_buf[index];
                service->srv_md[index].length       = service->srv_buf_size;
                service->srv_md[index].threshold    = PTL_MD_THRESH_INF;
                service->srv_md[index].options      = PTL_MD_OP_PUT;
                service->srv_md[index].user_ptr     = service;
                service->srv_md[index].eventq       = service->srv_eq_h;

                rc = PtlMDAttach(service->srv_me_h[index],
                                 service->srv_md[index],
                                 PTL_RETAIN, &(service->srv_md_h[index]));
                //CERROR("MDAttach (request MDs): %Lu\n",
                //(__u64)(service->srv_md_h[index]));

                CDEBUG(D_INFO, "Attach MD in ring, rc %d\n", rc);
                if (rc != PTL_OK) {
                        /* XXX cleanup */
                        CERROR("PtlMDAttach failed: %d\n", rc);
                        BUG();
                        spin_unlock(&service->srv_lock);
                        return rc;
                }
        } 
        
        spin_unlock(&service->srv_lock);
        return 0;
}
