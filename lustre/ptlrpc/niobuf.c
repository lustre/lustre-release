/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
#ifndef __KERNEL__
#include <liblustre.h>
#include <portals/lib-types.h>
#endif
#include <linux/obd_support.h>
#include <linux/lustre_net.h>
#include <linux/lustre_lib.h>
#include <linux/obd.h>

static int ptl_send_buf(struct ptlrpc_request *request,
                        struct ptlrpc_connection *conn, int portal)
{
        int rc;
        ptl_process_id_t remote_id;
        ptl_handle_md_t md_h;
        ptl_ack_req_t ack_req;

        LASSERT(conn);
        CDEBUG (D_INFO, "conn=%p ni %s nid "LPX64" on %s\n", 
                conn, conn->c_peer.peer_ni->pni_name,
                conn->c_peer.peer_nid, conn->c_peer.peer_ni->pni_name);

        request->rq_req_md.user_ptr = request;

        switch (request->rq_type) {
        case PTL_RPC_MSG_REQUEST:
                request->rq_reqmsg->type = HTON__u32(request->rq_type);
                request->rq_req_md.start = request->rq_reqmsg;
                request->rq_req_md.length = request->rq_reqlen;
                request->rq_req_md.eventq = conn->c_peer.peer_ni->pni_request_out_eq_h;
                break;
        case PTL_RPC_MSG_ERR:
        case PTL_RPC_MSG_REPLY:
                request->rq_repmsg->type = HTON__u32(request->rq_type);
                request->rq_req_md.start = request->rq_repmsg;
                request->rq_req_md.length = request->rq_replen;
                request->rq_req_md.eventq = conn->c_peer.peer_ni->pni_reply_out_eq_h;
                break;
        default:
                LBUG();
                return -1; /* notreached */
        }
        if (request->rq_flags & PTL_RPC_FL_WANT_ACK) {
                request->rq_req_md.threshold = 2; /* SENT and ACK */
                ack_req = PTL_ACK_REQ;
        } else {
                request->rq_req_md.threshold = 1;
                ack_req = PTL_NOACK_REQ;
        }
        request->rq_req_md.options = PTL_MD_OP_PUT;
        request->rq_req_md.user_ptr = request;

        if (OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_ACK | OBD_FAIL_ONCE)) {
                request->rq_req_md.options |= PTL_MD_ACK_DISABLE;
                obd_fail_loc |= OBD_FAIL_ONCE | OBD_FAILED;
        }

        rc = PtlMDBind(conn->c_peer.peer_ni->pni_ni_h, request->rq_req_md, &md_h);
        if (rc != 0) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LBUG();
                return rc;
        }

        remote_id.nid = conn->c_peer.peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %d bytes to portal %d, xid "LPD64"\n",
               request->rq_req_md.length, portal, request->rq_xid);

        if (!portal)
                LBUG();
        rc = PtlPut(md_h, ack_req, remote_id, portal, 0, request->rq_xid, 0, 0);
        if (rc != PTL_OK) {
                CERROR("PtlPut("LPU64", %d, "LPD64") failed: %d\n",
                       remote_id.nid, portal, request->rq_xid, rc);
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

int ptlrpc_bulk_put(struct ptlrpc_bulk_desc *desc)
{
        int rc;
        struct ptlrpc_peer *peer;
        struct list_head *tmp, *next;
        ptl_process_id_t remote_id;
        __u32 xid = 0;
        struct iovec *iov;
        ENTRY;

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                RETURN (-ENOMEM);

        peer = &desc->bd_connection->c_peer;

        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.eventq = peer->peer_ni->pni_bulk_put_source_eq_h;
        desc->bd_md.threshold = 2; /* SENT and ACK */
        desc->bd_md.options = PTL_MD_OP_PUT | PTL_MD_IOV;
        desc->bd_md.user_ptr = desc;

        atomic_set(&desc->bd_source_callback_count, 2);

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT(desc->bd_md.niov < desc->bd_page_count);

                if (desc->bd_md.niov == 0)
                        xid = bulk->bp_xid;
                LASSERT(xid == bulk->bp_xid);   /* should all be the same */

                iov[desc->bd_md.niov].iov_base = bulk->bp_buf;
                iov[desc->bd_md.niov].iov_len = bulk->bp_buflen;
                if (iov[desc->bd_md.niov].iov_len <= 0) {
                        CERROR("bad bp_buflen[%d] @ %p: %d\n", desc->bd_md.niov,
                               bulk->bp_buf, bulk->bp_buflen);
                        CERROR("desc: xid %u, pages %d, ptl %d, ref %d\n",
                               xid, desc->bd_page_count, desc->bd_portal,
                               atomic_read(&desc->bd_refcount));
                        LBUG();
                }
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }

        LASSERT(desc->bd_md.niov == desc->bd_page_count);
        LASSERT(desc->bd_md.niov != 0);

        rc = PtlMDBind(peer->peer_ni->pni_ni_h, desc->bd_md,
                       &desc->bd_md_h);

        ptlrpc_put_bulk_iov (desc, iov); /*move down to reduce latency to send*/

        if (rc != PTL_OK) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LBUG();
                RETURN(rc);
        }

        remote_id.nid = peer->peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %u pages %u bytes to portal %d on %s "
               "nid "LPX64" pid %d xid %d\n", 
               desc->bd_md.niov, desc->bd_md.length,
               desc->bd_portal, peer->peer_ni->pni_name,
               remote_id.nid, remote_id.pid, xid);

        rc = PtlPut(desc->bd_md_h, PTL_ACK_REQ, remote_id,
                    desc->bd_portal, 0, xid, 0, 0);
        if (rc != PTL_OK) {
                CERROR("PtlPut("LPU64", %d, %d) failed: %d\n",
                       remote_id.nid, desc->bd_portal, xid, rc);
                PtlMDUnlink(desc->bd_md_h);
                LBUG();
                RETURN(rc);
        }

        RETURN(0);
}

int ptlrpc_bulk_get(struct ptlrpc_bulk_desc *desc)
{
        int rc;
        struct ptlrpc_peer *peer;
        struct list_head *tmp, *next;
        ptl_process_id_t remote_id;
        __u32 xid = 0;
        struct iovec *iov;
        ENTRY;

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                RETURN (-ENOMEM);

        peer = &desc->bd_connection->c_peer;

        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.eventq = peer->peer_ni->pni_bulk_get_sink_eq_h;
        desc->bd_md.threshold = 2; /* SENT and REPLY */
        desc->bd_md.options = PTL_MD_OP_GET | PTL_MD_IOV;
        desc->bd_md.user_ptr = desc;

        atomic_set(&desc->bd_source_callback_count, 2);

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT(desc->bd_md.niov < desc->bd_page_count);

                if (desc->bd_md.niov == 0)
                        xid = bulk->bp_xid;
                LASSERT(xid == bulk->bp_xid);   /* should all be the same */

                iov[desc->bd_md.niov].iov_base = bulk->bp_buf;
                iov[desc->bd_md.niov].iov_len = bulk->bp_buflen;
                if (iov[desc->bd_md.niov].iov_len <= 0) {
                        CERROR("bad bulk %p bp_buflen[%d] @ %p: %d\n", bulk,
                               desc->bd_md.niov, bulk->bp_buf, bulk->bp_buflen);
                        CERROR("desc %p: xid %u, pages %d, ptl %d, ref %d\n",
                               desc, xid, desc->bd_page_count, desc->bd_portal,
                               atomic_read(&desc->bd_refcount));
                        LBUG();
                }
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }

        LASSERT(desc->bd_md.niov == desc->bd_page_count);
        LASSERT(desc->bd_md.niov != 0);

        rc = PtlMDBind(peer->peer_ni->pni_ni_h, desc->bd_md,
                       &desc->bd_md_h);

        ptlrpc_put_bulk_iov (desc, iov); /*move down to reduce latency to send*/

        if (rc != PTL_OK) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LBUG();
                RETURN(rc);
        }

        remote_id.nid = desc->bd_connection->c_peer.peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %u pages %u bytes to portal %d on %s "
               "nid "LPX64" pid %d xid %d\n", 
               desc->bd_md.niov, desc->bd_md.length,
               desc->bd_portal, peer->peer_ni->pni_name,
               remote_id.nid, remote_id.pid, xid);

        rc = PtlGet(desc->bd_md_h, remote_id, desc->bd_portal, 0, xid, 0);
        if (rc != PTL_OK) {
                CERROR("PtlGet("LPU64", %d, %d) failed: %d\n",
                       remote_id.nid, desc->bd_portal, xid, rc);
                PtlMDUnlink(desc->bd_md_h);
                LBUG();
                RETURN(rc);
        }

        RETURN(0);
}

static int ptlrpc_register_bulk_shared(struct ptlrpc_bulk_desc *desc)
{
        struct ptlrpc_peer *peer;
        struct list_head *tmp, *next;
        int rc;
        __u32 xid = 0;
        struct iovec *iov;
        ptl_process_id_t source_id;
        ENTRY;

        if (desc->bd_page_count > PTL_MD_MAX_IOV) {
                CERROR("iov longer than %d pages not supported (count=%d)\n",
                       PTL_MD_MAX_IOV, desc->bd_page_count);
                RETURN(-EINVAL);
        }

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                return (-ENOMEM);

        peer = &desc->bd_connection->c_peer;
        
        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.threshold = 1;
        desc->bd_md.user_ptr = desc;

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT(desc->bd_md.niov < desc->bd_page_count);

                if (desc->bd_md.niov == 0)
                        xid = bulk->bp_xid;
                LASSERT(xid == bulk->bp_xid);   /* should all be the same */

                iov[desc->bd_md.niov].iov_base = bulk->bp_buf;
                iov[desc->bd_md.niov].iov_len = bulk->bp_buflen;
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }

        LASSERT(desc->bd_md.niov == desc->bd_page_count);
        LASSERT(desc->bd_md.niov != 0);

        source_id.nid = desc->bd_connection->c_peer.peer_nid;
        source_id.pid = PTL_PID_ANY;

        rc = PtlMEAttach(peer->peer_ni->pni_ni_h,
                         desc->bd_portal, source_id, xid, 0,
                         PTL_UNLINK, PTL_INS_AFTER, &desc->bd_me_h);

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

        ptlrpc_put_bulk_iov (desc, iov);

        CDEBUG(D_NET, "Setup bulk sink buffers: %u pages %u bytes, xid %u, "
               "portal %u on %s\n", desc->bd_md.niov, desc->bd_md.length,
               xid, desc->bd_portal, peer->peer_ni->pni_name);

        RETURN(0);

 cleanup:
        ptlrpc_put_bulk_iov (desc, iov);
        ptlrpc_abort_bulk(desc);

        return rc;
}

int ptlrpc_register_bulk_get(struct ptlrpc_bulk_desc *desc)
{
        desc->bd_md.options = PTL_MD_OP_GET | PTL_MD_IOV;
        desc->bd_md.eventq = 
                desc->bd_connection->c_peer.peer_ni->pni_bulk_get_source_eq_h;

        return ptlrpc_register_bulk_shared(desc);
}

int ptlrpc_register_bulk_put(struct ptlrpc_bulk_desc *desc)
{
        desc->bd_md.options = PTL_MD_OP_PUT | PTL_MD_IOV;
        desc->bd_md.eventq = 
                desc->bd_connection->c_peer.peer_ni->pni_bulk_put_sink_eq_h;

        return ptlrpc_register_bulk_shared(desc);
}

int ptlrpc_abort_bulk(struct ptlrpc_bulk_desc *desc)
{
        int rc1, rc2;
        /* This should be safe: these handles are initialized to be
         * invalid in ptlrpc_prep_bulk() */
        rc1 = PtlMDUnlink(desc->bd_md_h);
        if (rc1 != PTL_OK)
                CERROR("PtlMDUnlink: %d\n", rc1);
        rc2 = PtlMEUnlink(desc->bd_me_h);
        if (rc2 != PTL_OK)
                CERROR("PtlMEUnlink: %d\n", rc2);

        return rc1 ? rc1 : rc2;
}

void obd_brw_set_addref(struct obd_brw_set *set)
{
        atomic_inc(&set->brw_refcount);
}

void obd_brw_set_add(struct obd_brw_set *set, struct ptlrpc_bulk_desc *desc)
{
        LASSERT(list_empty(&desc->bd_set_chain));

        ptlrpc_bulk_addref(desc);
        atomic_inc(&set->brw_desc_count);
        desc->bd_brw_set = set;
        list_add(&desc->bd_set_chain, &set->brw_desc_head);
}

void obd_brw_set_del(struct ptlrpc_bulk_desc *desc)
{
        atomic_dec(&desc->bd_brw_set->brw_desc_count);
        list_del_init(&desc->bd_set_chain);
        ptlrpc_bulk_decref(desc);
}

struct obd_brw_set *obd_brw_set_new(void)
{
        struct obd_brw_set *set;

        OBD_ALLOC(set, sizeof(*set));

        if (set != NULL) {
                init_waitqueue_head(&set->brw_waitq);
                INIT_LIST_HEAD(&set->brw_desc_head);
                atomic_set(&set->brw_refcount, 1);
                atomic_set(&set->brw_desc_count, 0);
        }

        return set;
}

static void obd_brw_set_free(struct obd_brw_set *set)
{
        struct list_head *tmp, *next;
        ENTRY;

        list_for_each_safe(tmp, next, &set->brw_desc_head) {
                struct ptlrpc_bulk_desc *desc =
                        list_entry(tmp, struct ptlrpc_bulk_desc, bd_set_chain);

                CERROR("Unfinished bulk descriptor: %p\n", desc);

                ptlrpc_abort_bulk(desc);
        }
        OBD_FREE(set, sizeof(*set));
        EXIT;
        return;
}

void obd_brw_set_decref(struct obd_brw_set *set)
{
        ENTRY;
        if (atomic_dec_and_test(&set->brw_refcount))
                obd_brw_set_free(set);
        EXIT;
}

int ptlrpc_reply(struct ptlrpc_service *svc, struct ptlrpc_request *req)
{
        if (req->rq_repmsg == NULL) {
                CERROR("bad: someone called ptlrpc_reply when they meant "
                       "ptlrpc_error\n");
                return -EINVAL;
        }

        /* FIXME: we need to increment the count of handled events */
        if (req->rq_type != PTL_RPC_MSG_ERR)
                req->rq_type = PTL_RPC_MSG_REPLY;
        //req->rq_repmsg->conn = req->rq_connection->c_remote_conn;
        //req->rq_repmsg->token = req->rq_connection->c_remote_token;
        req->rq_repmsg->status = HTON__u32(req->rq_status);
        return ptl_send_buf(req, req->rq_connection, svc->srv_rep_portal);
}

int ptlrpc_error(struct ptlrpc_service *svc, struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        if (!req->rq_repmsg) {
                rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen,
                                     &req->rq_repmsg);
                if (rc)
                        RETURN(rc);
        }


        req->rq_type = PTL_RPC_MSG_ERR;

        rc = ptlrpc_reply(svc, req);
        RETURN(rc);
}

int ptl_send_rpc(struct ptlrpc_request *request)
{
        int rc;
        char *repbuf;
        ptl_process_id_t source_id;

        ENTRY;

        if (request->rq_type != PTL_RPC_MSG_REQUEST) {
                CERROR("wrong packet type sent %d\n",
                       NTOH__u32(request->rq_reqmsg->type));
                LBUG();
                RETURN(EINVAL);
        }

        source_id.nid = request->rq_connection->c_peer.peer_nid;
        source_id.pid = PTL_PID_ANY;

        /* add a ref, which will be balanced in request_out_callback */
        ptlrpc_request_addref(request);
        if (request->rq_replen != 0) {
                if (request->rq_reply_md.start != NULL) {
                        rc = PtlMEUnlink(request->rq_reply_me_h);
                        if (rc != PTL_OK && rc != PTL_INV_ME) {
                                CERROR("rc %d\n", rc);
                                LBUG();
                        }
                        repbuf = (char *)request->rq_reply_md.start;
                        request->rq_repmsg = NULL;
                } else {
                        OBD_ALLOC(repbuf, request->rq_replen);
                        if (!repbuf) {
                                LBUG();
                                RETURN(ENOMEM);
                        }
                }

                rc = PtlMEAttach(request->rq_connection->c_peer.peer_ni->pni_ni_h,
                             request->rq_reply_portal,/* XXX FIXME bug 625069 */
                                 source_id, request->rq_xid, 0, PTL_UNLINK,
                                 PTL_INS_AFTER, &request->rq_reply_me_h);
                if (rc != PTL_OK) {
                        CERROR("PtlMEAttach failed: %d\n", rc);
                        LBUG();
                        GOTO(cleanup, rc);
                }

                request->rq_reply_md.start = repbuf;
                request->rq_reply_md.length = request->rq_replen;
                request->rq_reply_md.threshold = 1;
                request->rq_reply_md.options = PTL_MD_OP_PUT;
                request->rq_reply_md.user_ptr = request;
                request->rq_reply_md.eventq =
                        request->rq_connection->c_peer.peer_ni->pni_reply_in_eq_h;

                rc = PtlMDAttach(request->rq_reply_me_h, request->rq_reply_md,
                                 PTL_UNLINK, NULL);
                if (rc != PTL_OK) {
                        CERROR("PtlMDAttach failed: %d\n", rc);
                        LBUG();
                        GOTO(cleanup2, rc);
                }

                CDEBUG(D_NET, "Setup reply buffer: %u bytes, xid "LPU64
                       ", portal %u on %s\n",
                       request->rq_replen, request->rq_xid,
                       request->rq_reply_portal,
                       request->rq_connection->c_peer.peer_ni->pni_name);
        }

        /* Clear any flags that may be present from previous sends,
         * except for REPLAY, NO_RESEND and WANT_ACK. */
        request->rq_flags &= (PTL_RPC_FL_REPLAY | PTL_RPC_FL_NO_RESEND |
                              PTL_RPC_FL_WANT_ACK);
        rc = ptl_send_buf(request, request->rq_connection,
                          request->rq_request_portal);
        RETURN(rc);

 cleanup2:
        PtlMEUnlink(request->rq_reply_me_h);
 cleanup:
        OBD_FREE(repbuf, request->rq_replen);
        // up(&request->rq_client->cli_rpc_sem);

        return rc;
}

void ptlrpc_link_svc_me(struct ptlrpc_request_buffer_desc *rqbd)
{
        struct ptlrpc_srv_ni *srv_ni = rqbd->rqbd_srv_ni;
        struct ptlrpc_service *service = srv_ni->sni_service;
        static ptl_process_id_t match_id = {PTL_NID_ANY, PTL_PID_ANY};
        int rc;
        ptl_md_t dummy;
        ptl_handle_md_t md_h;

        LASSERT(atomic_read(&rqbd->rqbd_refcount) == 0);

        CDEBUG(D_NET, "PtlMEAttach: portal %d on %s h %lx.%lx\n",
               service->srv_req_portal, srv_ni->sni_ni->pni_name,
               srv_ni->sni_ni->pni_ni_h.nal_idx,
               srv_ni->sni_ni->pni_ni_h.handle_idx);

        /* Attach the leading ME on which we build the ring */
        rc = PtlMEAttach(srv_ni->sni_ni->pni_ni_h, service->srv_req_portal,
                         match_id, 0, ~0,
                         PTL_UNLINK, PTL_INS_AFTER, &rqbd->rqbd_me_h);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                LBUG();
        }

        dummy.start      = rqbd->rqbd_buffer;
        dummy.length     = service->srv_buf_size;
        dummy.max_size   = service->srv_max_req_size;
        dummy.threshold  = PTL_MD_THRESH_INF;
        dummy.options    = PTL_MD_OP_PUT | PTL_MD_MAX_SIZE | PTL_MD_AUTO_UNLINK;
        dummy.user_ptr   = rqbd;
        dummy.eventq     = srv_ni->sni_eq_h;

        atomic_inc(&srv_ni->sni_nrqbds_receiving);
        atomic_set(&rqbd->rqbd_refcount, 1);   /* 1 ref for portals */

        rc = PtlMDAttach(rqbd->rqbd_me_h, dummy, PTL_UNLINK, &md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach failed: %d\n", rc);
                LBUG();
#warning proper cleanup required
                PtlMEUnlink (rqbd->rqbd_me_h);
                atomic_set(&rqbd->rqbd_refcount, 0);
                atomic_dec(&srv_ni->sni_nrqbds_receiving);
        }
}
