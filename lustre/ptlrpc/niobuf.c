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
#include "ptlrpc_internal.h"

static int ptl_send_buf(struct ptlrpc_request *request,
                        struct ptlrpc_connection *conn, int portal)
{
        int rc;
        int rc2;
        ptl_process_id_t remote_id;
        ptl_handle_md_t md_h;
        ptl_ack_req_t ack_req;
        char str[PTL_NALFMT_SIZE];

        LASSERT (portal != 0);
        LASSERT (conn != NULL);
        CDEBUG (D_INFO, "conn=%p ni %s nid "LPX64" (%s) on %s\n",
                conn, conn->c_peer.peer_ni->pni_name,
                conn->c_peer.peer_nid,
                portals_nid2str(conn->c_peer.peer_ni->pni_number,
                                conn->c_peer.peer_nid, str),
                conn->c_peer.peer_ni->pni_name);

        request->rq_req_md.user_ptr = request;

        switch (request->rq_type) {
        case PTL_RPC_MSG_REQUEST:
                request->rq_reqmsg->type = request->rq_type;
                request->rq_req_md.start = request->rq_reqmsg;
                request->rq_req_md.length = request->rq_reqlen;
                request->rq_req_md.eventq =
                        conn->c_peer.peer_ni->pni_request_out_eq_h;
                LASSERT (!request->rq_want_ack);
                break;
        case PTL_RPC_MSG_ERR:
        case PTL_RPC_MSG_REPLY:
                request->rq_repmsg->type = request->rq_type;
                request->rq_req_md.start = request->rq_repmsg;
                request->rq_req_md.length = request->rq_replen;
                request->rq_req_md.eventq =
                        conn->c_peer.peer_ni->pni_reply_out_eq_h;
                break;
        default:
                LBUG();
                return -1; /* notreached */
        }
        if (request->rq_want_ack) {
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

        /* NB if the send fails, we back out of the send and return
         * failure; it's down to the caller to handle missing callbacks */

        rc = PtlMDBind(conn->c_peer.peer_ni->pni_ni_h, request->rq_req_md,
                       &md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LASSERT (rc == PTL_NOSPACE);
                RETURN (-ENOMEM);
        }
        if (request->rq_type != PTL_RPC_MSG_REQUEST)
                memcpy(&request->rq_reply_md_h, &md_h, sizeof(md_h));

        remote_id.nid = conn->c_peer.peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %d bytes to portal %d, xid "LPD64"\n",
               request->rq_req_md.length, portal, request->rq_xid);

        rc = PtlPut(md_h, ack_req, remote_id, portal, 0, request->rq_xid, 0, 0);
        if (rc != PTL_OK) {
                CERROR("PtlPut("LPU64", %d, "LPD64") failed: %d\n",
                       remote_id.nid, portal, request->rq_xid, rc);
                rc2 = PtlMDUnlink(md_h);
                LASSERT (rc2 == PTL_OK);
                RETURN ((rc == PTL_NOSPACE) ? -ENOMEM : -ECOMM);
        }

        return 0;
}

static inline ptl_kiov_t *
ptlrpc_get_bulk_iov (struct ptlrpc_bulk_desc *desc)
{
        ptl_kiov_t *iov;

        if (desc->bd_page_count <= sizeof (desc->bd_iov)/sizeof (*iov))
                return (desc->bd_iov);

        OBD_ALLOC (iov, desc->bd_page_count * sizeof (*iov));
        if (iov == NULL)
                LBUG();

        return (iov);
}

static inline void
ptlrpc_put_bulk_iov (struct ptlrpc_bulk_desc *desc, ptl_kiov_t *iov)
{
        if (desc->bd_page_count <= sizeof (desc->bd_iov)/sizeof (*iov))
                return;

        OBD_FREE (iov, desc->bd_page_count * sizeof (*iov));
}

int ptlrpc_bulk_put(struct ptlrpc_bulk_desc *desc)
{
        int rc;
        int rc2;
        struct ptlrpc_peer *peer;
        struct list_head *tmp, *next;
        ptl_process_id_t remote_id;
        ptl_kiov_t *iov;
        __u64 xid;
        ENTRY;

        /* NB no locking required until desc is on the network */
        LASSERT (!desc->bd_network_rw);
        LASSERT (desc->bd_type == BULK_PUT_SOURCE);
        desc->bd_complete = 0;

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                RETURN (-ENOMEM);

        peer = &desc->bd_export->exp_connection->c_peer;

        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.eventq = peer->peer_ni->pni_bulk_put_source_eq_h;
        desc->bd_md.threshold = 2; /* SENT and ACK */
        desc->bd_md.options = PTL_MD_OP_PUT | PTL_MD_KIOV;
        desc->bd_md.user_ptr = desc;

        desc->bd_callback_count = 2;

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT(desc->bd_md.niov < desc->bd_page_count);

                iov[desc->bd_md.niov].kiov_page = bulk->bp_page;
                iov[desc->bd_md.niov].kiov_offset = bulk->bp_pageoffset;
                iov[desc->bd_md.niov].kiov_len = bulk->bp_buflen;

                LASSERT (iov[desc->bd_md.niov].kiov_offset +
                         iov[desc->bd_md.niov].kiov_len <= PAGE_SIZE);
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }

        /* NB total length may be 0 for a read past EOF, so we send a 0
         * length bulk, since the client expects a bulk event. */
        LASSERT(desc->bd_md.niov == desc->bd_page_count);

        rc = PtlMDBind(peer->peer_ni->pni_ni_h, desc->bd_md,
                       &desc->bd_md_h);

        ptlrpc_put_bulk_iov (desc, iov); /*move down to reduce latency to send*/

        if (rc != PTL_OK) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LASSERT (rc == PTL_NOSPACE);
                RETURN(-ENOMEM);
        }

        /* Client's bulk and reply matchbits are the same */
        xid = desc->bd_req->rq_xid;
        remote_id.nid = peer->peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Sending %u pages %u bytes to portal %d on %s "
               "nid "LPX64" pid %d xid "LPX64"\n",
               desc->bd_md.niov, desc->bd_md.length,
               desc->bd_portal, peer->peer_ni->pni_name,
               remote_id.nid, remote_id.pid, xid);

        desc->bd_network_rw = 1;
        rc = PtlPut(desc->bd_md_h, PTL_ACK_REQ, remote_id,
                    desc->bd_portal, 0, xid, 0, 0);
        if (rc != PTL_OK) {
                desc->bd_network_rw = 0;
                CERROR("PtlPut("LPU64", %d, "LPX64") failed: %d\n",
                       remote_id.nid, desc->bd_portal, xid, rc);
                rc2 = PtlMDUnlink(desc->bd_md_h);
                LASSERT (rc2 == PTL_OK);
                RETURN((rc == PTL_NOSPACE) ? -ENOMEM : -ECOMM);
        }

        RETURN(0);
}

int ptlrpc_bulk_get(struct ptlrpc_bulk_desc *desc)
{
        int rc;
        int rc2;
        struct ptlrpc_peer *peer;
        struct list_head *tmp, *next;
        ptl_process_id_t remote_id;
        ptl_kiov_t *iov;
        __u64 xid;
        ENTRY;

        /* NB no locking required until desc is on the network */
        LASSERT (!desc->bd_network_rw);
        LASSERT (desc->bd_type == BULK_GET_SINK);
        desc->bd_complete = 0;

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                RETURN(-ENOMEM);

        peer = &desc->bd_export->exp_connection->c_peer;

        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.eventq = peer->peer_ni->pni_bulk_get_sink_eq_h;
        desc->bd_md.threshold = 2; /* SENT and REPLY */
        desc->bd_md.options = PTL_MD_OP_GET | PTL_MD_KIOV;
        desc->bd_md.user_ptr = desc;

        desc->bd_callback_count = 2;

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT(desc->bd_md.niov < desc->bd_page_count);

                iov[desc->bd_md.niov].kiov_page = bulk->bp_page;
                iov[desc->bd_md.niov].kiov_len = bulk->bp_buflen;
                iov[desc->bd_md.niov].kiov_offset = bulk->bp_pageoffset;

                LASSERT (iov[desc->bd_md.niov].kiov_offset +
                         iov[desc->bd_md.niov].kiov_len <= PAGE_SIZE);
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }

        LASSERT(desc->bd_md.niov == desc->bd_page_count);
        LASSERT(desc->bd_md.niov != 0);

        rc = PtlMDBind(peer->peer_ni->pni_ni_h, desc->bd_md, &desc->bd_md_h);

        ptlrpc_put_bulk_iov(desc, iov); /*move down to reduce latency to send*/

        if (rc != PTL_OK) {
                CERROR("PtlMDBind failed: %d\n", rc);
                LASSERT (rc == PTL_NOSPACE);
                RETURN(-ENOMEM);
        }

        /* Client's bulk and reply matchbits are the same */
        xid = desc->bd_req->rq_xid;
        remote_id.nid = desc->bd_export->exp_connection->c_peer.peer_nid;
        remote_id.pid = 0;

        CDEBUG(D_NET, "Fetching %u pages %u bytes from portal %d on %s "
               "nid "LPX64" pid %d xid "LPX64"\n",
               desc->bd_md.niov, desc->bd_md.length, desc->bd_portal,
               peer->peer_ni->pni_name, remote_id.nid, remote_id.pid,
               xid);

        desc->bd_network_rw = 1;
        rc = PtlGet(desc->bd_md_h, remote_id, desc->bd_portal, 0,
                    xid, 0);
        if (rc != PTL_OK) {
                desc->bd_network_rw = 0;
                CERROR("PtlGet("LPU64", %d, "LPX64") failed: %d\n",
                       remote_id.nid, desc->bd_portal, xid, rc);
                rc2 = PtlMDUnlink(desc->bd_md_h);
                LASSERT (rc2 == PTL_OK);
                RETURN((rc == PTL_NOSPACE) ? -ENOMEM : -ECOMM);
        }

        RETURN(0);
}

void ptlrpc_abort_bulk (struct ptlrpc_bulk_desc *desc)
{
        /* Server side bulk abort. Idempotent. Not thread-safe (i.e. only
         * serialises with completion callback) */
        unsigned long      flags;
        struct l_wait_info lwi;
        int                callback_count;
        int                rc;

        LASSERT (!in_interrupt ());             /* might sleep */

        /* NB. server-side bulk gets 2 events, so we have to keep trying to
         * unlink the MD until all callbacks have happened, or
         * PtlMDUnlink() returns OK or INVALID */
 again:
        spin_lock_irqsave (&desc->bd_lock, flags);
        if (!desc->bd_network_rw) {
                /* completed or never even registered. NB holding bd_lock
                 * guarantees callback has completed if it ran. */
                spin_unlock_irqrestore (&desc->bd_lock, flags);
                return;
        }

        /* sample callback count while we have the lock */
        callback_count = desc->bd_callback_count;
        spin_unlock_irqrestore (&desc->bd_lock, flags);

        rc = PtlMDUnlink (desc->bd_md_h);
        switch (rc) {
        default:
                CERROR("PtlMDUnlink returned %d\n", rc);
                LBUG ();
        case PTL_OK:                    /* Won the race with the network */
                LASSERT (!desc->bd_complete); /* Not all callbacks ran */
                desc->bd_network_rw = 0;
                return;

        case PTL_MD_INUSE:              /* MD is being accessed right now */
                for (;;) {
                        /* Network access will complete in finite time but the
                         * timeout lets us CERROR for visibility */
                        lwi = LWI_TIMEOUT (10 * HZ, NULL, NULL);
                        rc = l_wait_event(desc->bd_waitq,
                                          desc->bd_callback_count !=
                                          callback_count, &lwi);
                        if (rc == -ETIMEDOUT) {
                                CERROR("Unexpectedly long timeout: desc %p\n",
                                       desc);
                                continue;
                        }
                        LASSERT (rc == 0);
                        break;
                }
                /* go back and try again... */
                goto again;

        case PTL_INV_MD:            /* Lost the race with completion */
                LASSERT (desc->bd_complete);    /* Callbacks all ran */
                LASSERT (!desc->bd_network_rw);
                return;
        }
}

int ptlrpc_register_bulk (struct ptlrpc_request *req)
{
        struct ptlrpc_bulk_desc *desc = req->rq_bulk;
        struct ptlrpc_peer *peer;
        struct list_head *tmp, *next;
        int rc;
        int rc2;
        ptl_kiov_t *iov;
        ptl_process_id_t source_id;
        ENTRY;

        /* NB no locking required until desc is on the network */
        LASSERT (!desc->bd_network_rw);
        LASSERT (desc->bd_page_count <= PTL_MD_MAX_PAGES);
        LASSERT (desc->bd_req != NULL);
        LASSERT (desc->bd_type == BULK_PUT_SINK ||
                 desc->bd_type == BULK_GET_SOURCE);

        desc->bd_complete = 0;

        iov = ptlrpc_get_bulk_iov (desc);
        if (iov == NULL)
                return (-ENOMEM);

        peer = &desc->bd_import->imp_connection->c_peer;

        desc->bd_md.start = iov;
        desc->bd_md.niov = 0;
        desc->bd_md.length = 0;
        desc->bd_md.threshold = 1;
        desc->bd_md.user_ptr = desc;

        if (desc->bd_type == BULK_GET_SOURCE) {
                desc->bd_md.options = PTL_MD_OP_GET | PTL_MD_KIOV;
                desc->bd_md.eventq = peer->peer_ni->pni_bulk_get_source_eq_h;
        } else {
                desc->bd_md.options = PTL_MD_OP_PUT | PTL_MD_KIOV;
                desc->bd_md.eventq = peer->peer_ni->pni_bulk_put_sink_eq_h;
        }

        list_for_each_safe(tmp, next, &desc->bd_page_list) {
                struct ptlrpc_bulk_page *bulk;
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                LASSERT(desc->bd_md.niov < desc->bd_page_count);

                iov[desc->bd_md.niov].kiov_page = bulk->bp_page;
                iov[desc->bd_md.niov].kiov_len = bulk->bp_buflen;
                iov[desc->bd_md.niov].kiov_offset = bulk->bp_pageoffset;

                LASSERT (bulk->bp_pageoffset + bulk->bp_buflen <= PAGE_SIZE);
                desc->bd_md.niov++;
                desc->bd_md.length += bulk->bp_buflen;
        }

        LASSERT(desc->bd_md.niov == desc->bd_page_count);
        LASSERT(desc->bd_md.niov != 0);

        /* XXX Registering the same xid on retried bulk makes my head
         * explode trying to understand how the original request's bulk
         * might interfere with the retried request -eeb */
        LASSERT (!desc->bd_registered || req->rq_xid != desc->bd_last_xid);
        desc->bd_registered = 1;
        desc->bd_last_xid = desc->bd_last_xid;

        source_id.nid = desc->bd_import->imp_connection->c_peer.peer_nid;
        source_id.pid = PTL_PID_ANY;

        rc = PtlMEAttach(peer->peer_ni->pni_ni_h,
                         desc->bd_portal, source_id, req->rq_xid, 0,
                         PTL_UNLINK, PTL_INS_AFTER, &desc->bd_me_h);

        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                LASSERT (rc == PTL_NOSPACE);
                GOTO(out, rc = -ENOMEM);
        }

        /* About to let the network at it... */
        desc->bd_network_rw = 1;
        rc = PtlMDAttach(desc->bd_me_h, desc->bd_md, PTL_UNLINK,
                         &desc->bd_md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach failed: %d\n", rc);
                LASSERT (rc == PTL_NOSPACE);
                desc->bd_network_rw = 0;
                rc2 = PtlMEUnlink (desc->bd_me_h);
                LASSERT (rc2 == PTL_OK);
                GOTO(out, rc = -ENOMEM);
        }
        rc = 0;

        CDEBUG(D_NET, "Setup bulk %s buffers: %u pages %u bytes, xid "LPX64", "
               "portal %u on %s\n",
               desc->bd_type == BULK_GET_SOURCE ? "get-source" : "put-sink",
               desc->bd_md.niov, desc->bd_md.length,
               req->rq_xid, desc->bd_portal, peer->peer_ni->pni_name);

 out:
        ptlrpc_put_bulk_iov (desc, iov);
        RETURN(rc);
}

void ptlrpc_unregister_bulk (struct ptlrpc_request *req)
{
        /* Disconnect a bulk desc from the network. Idempotent. Not
         * thread-safe (i.e. only interlocks with completion callback). */
        struct ptlrpc_bulk_desc *desc = req->rq_bulk;
        wait_queue_head_t       *wq;
        unsigned long            flags;
        struct l_wait_info       lwi;
        int                      rc;

        LASSERT (!in_interrupt ());             /* might sleep */

        spin_lock_irqsave (&desc->bd_lock, flags);
        if (!desc->bd_network_rw) {     /* completed or never even registered */
                spin_unlock_irqrestore (&desc->bd_lock, flags);
                return;
        }
        spin_unlock_irqrestore (&desc->bd_lock, flags);

        LASSERT (desc->bd_req == req);     /* NB bd_req NULL until registered */

        /* NB...
         * 1. If the MD unlink is successful, the ME gets unlinked too.
         * 2. Since client-side bulk only gets a single event and a
         * .. threshold of 1.  If the MD was inuse at the first link
         * .. attempt, the callback is due any minute, and the MD/ME will
         * .. unlink themselves.
         */
        rc = PtlMDUnlink (desc->bd_md_h);
        switch (rc) {
        default:
                CERROR("PtlMDUnlink returned %d\n", rc);
                LBUG ();
        case PTL_OK:                          /* Won the race with completion */
                LASSERT (!desc->bd_complete);   /* Callback hasn't happened */
                desc->bd_network_rw = 0;
                return;
        case PTL_MD_INUSE:                  /* MD is being accessed right now */
                for (;;) {
                        /* Network access will complete in finite time but the
                         * timeout lets us CERROR for visibility */
                        if (desc->bd_req->rq_set != NULL)
                                wq = &req->rq_set->set_waitq;
                        else
                                wq = &req->rq_wait_for_rep;
                        lwi = LWI_TIMEOUT (10 * HZ, NULL, NULL);
                        rc = l_wait_event(*wq, ptlrpc_bulk_complete(desc), &lwi);
                        LASSERT (rc == 0 || rc == -ETIMEDOUT);
                        if (rc == 0)
                                break;
                        CERROR ("Unexpectedly long timeout: desc %p\n", desc);
                        LBUG();
                }
                /* Fall through */
        case PTL_INV_MD:                     /* Lost the race with completion */
                LASSERT (desc->bd_complete);/* Callback has run to completion */
                LASSERT (!desc->bd_network_rw);
                return;
        }
}

int ptlrpc_reply(struct ptlrpc_request *req)
{
        unsigned long flags;
        int rc;

        /* We must already have a reply buffer (only ptlrpc_error() may be
         * called without one).  We must also have a request buffer which
         * is either the actual (swabbed) incoming request, or a saved copy
         * if this is a req saved in target_queue_final_reply(). */
        LASSERT (req->rq_repmsg != NULL);
        LASSERT (req->rq_reqmsg != NULL);

        /* FIXME: we need to increment the count of handled events */
        if (req->rq_type != PTL_RPC_MSG_ERR)
                req->rq_type = PTL_RPC_MSG_REPLY;

        req->rq_repmsg->status = req->rq_status;
        req->rq_repmsg->opc = req->rq_reqmsg->opc;

        init_waitqueue_head(&req->rq_wait_for_rep);
        rc = ptl_send_buf(req, req->rq_connection, req->rq_svc->srv_rep_portal);
        if (rc != 0) {
                /* Do what the callback handler would have done */
                OBD_FREE (req->rq_repmsg, req->rq_replen);

                spin_lock_irqsave (&req->rq_lock, flags);
                req->rq_want_ack = 0;
                spin_unlock_irqrestore (&req->rq_lock, flags);
        }
        return rc;
}

int ptlrpc_error(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        if (!req->rq_repmsg) {
                rc = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc)
                        RETURN(rc);
        }


        req->rq_type = PTL_RPC_MSG_ERR;

        rc = ptlrpc_reply(req);
        RETURN(rc);
}

int ptl_send_rpc(struct ptlrpc_request *request)
{
        int rc;
        int rc2;
        unsigned long flags;
        ptl_process_id_t source_id;
        ptl_handle_me_t  reply_me_h;
        ENTRY;

        LASSERT (request->rq_type == PTL_RPC_MSG_REQUEST);

        /* If this is a re-transmit, we're required to have disengaged
         * cleanly from the previous attempt */
        LASSERT (!request->rq_receiving_reply);

        if (request->rq_bulk != NULL) {
                rc = ptlrpc_register_bulk (request);
                if (rc != 0)
                        RETURN(rc);
        }

        request->rq_reqmsg->handle = request->rq_import->imp_remote_handle;
        request->rq_reqmsg->conn_cnt = request->rq_import->imp_conn_cnt;

        source_id.nid = request->rq_connection->c_peer.peer_nid;
        source_id.pid = PTL_PID_ANY;

        LASSERT (request->rq_replen != 0);
        if (request->rq_repmsg == NULL)
                OBD_ALLOC(request->rq_repmsg, request->rq_replen);
        if (request->rq_repmsg == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        rc = PtlMEAttach(request->rq_connection->c_peer.peer_ni->pni_ni_h,
                         request->rq_reply_portal, /* XXX FIXME bug 249 */
                         source_id, request->rq_xid, 0, PTL_UNLINK,
                         PTL_INS_AFTER, &reply_me_h);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                LASSERT (rc == PTL_NOSPACE);
                LBUG();
                GOTO(cleanup, rc = -ENOMEM);
        }

        request->rq_reply_md.start = request->rq_repmsg;
        request->rq_reply_md.length = request->rq_replen;
        request->rq_reply_md.threshold = 1;
        request->rq_reply_md.options = PTL_MD_OP_PUT;
        request->rq_reply_md.user_ptr = request;
        request->rq_reply_md.eventq =
                request->rq_connection->c_peer.peer_ni->pni_reply_in_eq_h;

        rc = PtlMDAttach(reply_me_h, request->rq_reply_md,
                         PTL_UNLINK, &request->rq_reply_md_h);
        if (rc != PTL_OK) {
                CERROR("PtlMDAttach failed: %d\n", rc);
                LASSERT (rc == PTL_NOSPACE);
                LBUG();
                GOTO(cleanup2, rc -ENOMEM);
        }

        CDEBUG(D_NET, "Setup reply buffer: %u bytes, xid "LPU64
               ", portal %u on %s\n",
               request->rq_replen, request->rq_xid,
               request->rq_reply_portal,
               request->rq_connection->c_peer.peer_ni->pni_name);

        ptlrpc_request_addref(request);        /* 1 ref for the SENT callback */

        spin_lock_irqsave (&request->rq_lock, flags);
        request->rq_receiving_reply = 1;
        /* Clear any flags that may be present from previous sends. */
        request->rq_replied = 0;
        request->rq_err = 0;
        request->rq_timedout = 0;
        request->rq_resend = 0;
        request->rq_restart = 0;
        spin_unlock_irqrestore (&request->rq_lock, flags);

        request->rq_sent = LTIME_S(CURRENT_TIME);
        ptlrpc_pinger_sending_on_import(request->rq_import);
        rc = ptl_send_buf(request, request->rq_connection,
                          request->rq_request_portal);
        if (rc == 0) {
                ptlrpc_lprocfs_rpc_sent(request);
                RETURN(rc);
        }

        spin_lock_irqsave (&request->rq_lock, flags);
        request->rq_receiving_reply = 0;
        spin_unlock_irqrestore (&request->rq_lock, flags);
        ptlrpc_req_finished (request);          /* drop callback ref */
 cleanup2:
        /* MEUnlink is safe; the PUT didn't even get off the ground, and
         * nobody apart from the PUT's target has the right nid+XID to
         * access the reply buffer. */
        rc2 = PtlMEUnlink(reply_me_h);
        LASSERT (rc2 == PTL_OK);
 cleanup:
        OBD_FREE(request->rq_repmsg, request->rq_replen);
        request->rq_repmsg = NULL;
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

        CDEBUG(D_NET, "PtlMEAttach: portal %d on %s h %lx."LPX64"\n",
               service->srv_req_portal, srv_ni->sni_ni->pni_name,
               srv_ni->sni_ni->pni_ni_h.nal_idx,
               srv_ni->sni_ni->pni_ni_h.cookie);

        /* Attach the leading ME on which we build the ring */
        rc = PtlMEAttach(srv_ni->sni_ni->pni_ni_h, service->srv_req_portal,
                         match_id, 0, ~0,
                         PTL_UNLINK, PTL_INS_AFTER, &rqbd->rqbd_me_h);
        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                /* BUG 1191 */
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
                LASSERT (rc == PTL_NOSPACE);
                LBUG();
                /* BUG 1191 */
                PtlMEUnlink (rqbd->rqbd_me_h);
                atomic_set(&rqbd->rqbd_refcount, 0);
                atomic_dec(&srv_ni->sni_nrqbds_receiving);
        }
}
