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

#include <linux/module.h>
#include <linux/lustre_net.h>

ptl_handle_eq_t request_out_eq, reply_in_eq, reply_out_eq, bulk_source_eq,
        bulk_sink_eq;
static const ptl_handle_ni_t *socknal_nip = NULL, *qswnal_nip = NULL;

/*
 *  Free the packet when it has gone out
 */
static int request_out_callback(ptl_event_t *ev)
{
        ENTRY;

        if (ev->type != PTL_EVENT_SENT) {
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        RETURN(1);
}


/*
 *  Free the packet when it has gone out
 */
static int reply_out_callback(ptl_event_t *ev)
{
        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                OBD_FREE(ev->mem_desc.start, ev->mem_desc.length);
        } else {
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        RETURN(1);
}

/*
 * Wake up the thread waiting for the reply once it comes in.
 */
static int reply_in_callback(ptl_event_t *ev)
{
        struct ptlrpc_request *req = ev->mem_desc.user_ptr;
        ENTRY;

        if (req->rq_xid == 0x5a5a5a5a) {
                CERROR("Reply received for freed request!  Probably a missing "
                       "ptlrpc_abort()\n");
                LBUG();
        }

        if (req->rq_xid != ev->match_bits) {
                CERROR("Reply packet for wrong request\n");
                LBUG(); 
        }

        if (ev->type == PTL_EVENT_PUT) {
                req->rq_repmsg = ev->mem_desc.start + ev->offset;
                barrier();
                wake_up(&req->rq_wait_for_rep);
        } else {
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        RETURN(1);
}

int request_in_callback(ptl_event_t *ev)
{
        struct ptlrpc_service *service = ev->mem_desc.user_ptr;

        if (ev->rlength != ev->mlength)
                CERROR("Warning: Possibly truncated rpc (%d/%d)\n",
                       ev->mlength, ev->rlength);

        if (ev->type == PTL_EVENT_PUT)
                wake_up(&service->srv_waitq);
        else
                CERROR("Unexpected event type: %d\n", ev->type);

        return 0;
}

static int bulk_source_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_page *bulk = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_desc *desc = bulk->b_desc;
        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                CDEBUG(D_NET, "got SENT event\n");
        } else if (ev->type == PTL_EVENT_ACK) {
                CDEBUG(D_NET, "got ACK event\n");
                if (bulk->b_cb != NULL)
                        bulk->b_cb(bulk);
                if (atomic_dec_and_test(&desc->b_pages_remaining)) {
                        desc->b_flags |= PTL_BULK_FL_SENT;
                        wake_up(&desc->b_waitq);
                        if (desc->b_cb != NULL)
                                desc->b_cb(desc, desc->b_cb_data);
                }
        } else {
                CERROR("Unexpected event type!\n");
                LBUG();
        }

        RETURN(1);
}

static int bulk_sink_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_page *bulk = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_desc *desc = bulk->b_desc;
        ENTRY;

        if (ev->type == PTL_EVENT_PUT) {
                if (bulk->b_buf != ev->mem_desc.start + ev->offset)
                        CERROR("bulkbuf != mem_desc -- why?\n");
                if (bulk->b_cb != NULL)
                        bulk->b_cb(bulk);
                if (atomic_dec_and_test(&desc->b_pages_remaining)) {
                        desc->b_flags |= PTL_BULK_FL_RCVD;
                        wake_up(&desc->b_waitq);
                        if (desc->b_cb != NULL)
                                desc->b_cb(desc, desc->b_cb_data);
                }
        } else {
                CERROR("Unexpected event type!\n");
                LBUG();
        }

        RETURN(1);
}

int ptlrpc_init_portals(void)
{
        int rc;
        ptl_handle_ni_t ni;

        socknal_nip = inter_module_get_request("ksocknal_ni", "ksocknal");
        qswnal_nip = inter_module_get_request("kqswnal_ni", "kqswnal");
        if (socknal_nip == NULL && qswnal_nip == NULL) {
                CERROR("get_ni failed: is a NAL module loaded?\n");
                return -EIO;
        }

        /* Use the qswnal if it's there */
        if (qswnal_nip != NULL)
                ni = *qswnal_nip;
        else
                ni = *socknal_nip;

        rc = PtlEQAlloc(ni, 128, request_out_callback, &request_out_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, reply_out_callback, &reply_out_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, reply_in_callback, &reply_in_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, bulk_source_callback, &bulk_source_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, bulk_sink_callback, &bulk_sink_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        return rc;
}

void ptlrpc_exit_portals(void)
{
        PtlEQFree(request_out_eq);
        PtlEQFree(reply_out_eq);
        PtlEQFree(reply_in_eq);
        PtlEQFree(bulk_source_eq);
        PtlEQFree(bulk_sink_eq);

        if (qswnal_nip != NULL)
                inter_module_put("kqswnal_ni");
        if (socknal_nip != NULL)
                inter_module_put("ksocknal_ni");
}
