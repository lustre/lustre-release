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
#include <linux/obd_support.h>
#include <linux/lustre_net.h>

ptl_handle_eq_t request_out_eq, reply_in_eq, reply_out_eq, bulk_source_eq,
        bulk_sink_eq;
static const ptl_handle_ni_t *socknal_nip = NULL, *qswnal_nip = NULL, *gmnal_nip = NULL;

/*
 *  Free the packet when it has gone out
 */
static int request_out_callback(ptl_event_t *ev)
{
        struct ptlrpc_request *req = ev->mem_desc.user_ptr;
        ENTRY;

        LASSERT ((ev->mem_desc.options & PTL_MD_IOV) == 0); /* requests always contiguous */

        if (ev->type != PTL_EVENT_SENT) {
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        ptlrpc_req_finished(req);
        RETURN(1);
}


/*
 *  Free the packet when it has gone out
 */
static int reply_out_callback(ptl_event_t *ev)
{
        ENTRY;

        LASSERT ((ev->mem_desc.options & PTL_MD_IOV) == 0); /* replies always contiguous */

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

        LASSERT ((ev->mem_desc.options & PTL_MD_IOV) == 0); /* replies always contiguous */

        if (req->rq_xid == 0x5a5a5a5a5a5a5a5a) {
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
        struct ptlrpc_request_buffer_desc *rqbd = ev->mem_desc.user_ptr;
        struct ptlrpc_service *service = rqbd->rqbd_service;

        LASSERT ((ev->mem_desc.options & PTL_MD_IOV) == 0); /* requests always contiguous */
        LASSERT (ev->type == PTL_EVENT_PUT);    /* we only enable puts */
        LASSERT (atomic_read (&service->srv_nrqbds_receiving) > 0);
        LASSERT (atomic_read (&rqbd->rqbd_refcount) > 0);
        
        if (ev->rlength != ev->mlength)
                CERROR("Warning: Possibly truncated rpc (%d/%d)\n",
                       ev->mlength, ev->rlength);

        if (ptl_is_valid_handle (&ev->unlinked_me))
        {
                /* This is the last request to be received into this
                 * request buffer.  We don't bump the refcount, since the
                 * thread servicing this event is effectively taking over
                 * portals' reference.
                 */
#warning ev->unlinked_me.nal_idx is not set properly in a callback
                LASSERT (ev->unlinked_me.handle_idx == rqbd->rqbd_me_h.handle_idx);

                if (atomic_dec_and_test (&service->srv_nrqbds_receiving)) /* we're off-air */
                {
                        CERROR ("All request buffers busy\n");
                        /* we'll probably start dropping packets in portals soon */
                }
        }
        else
                atomic_inc (&rqbd->rqbd_refcount); /* +1 ref for service thread */

        wake_up(&service->srv_waitq);

        return 0;
}

static int bulk_source_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_page *bulk;
        struct list_head        *tmp;
        struct list_head        *next;
        ENTRY;

        CDEBUG(D_NET, "got %s event %d\n",
               (ev->type == PTL_EVENT_SENT) ? "SENT" :
               (ev->type == PTL_EVENT_ACK)  ? "ACK"  : "UNEXPECTED", ev->type);

        LASSERT (ev->type == PTL_EVENT_SENT || ev->type == PTL_EVENT_ACK);

        LASSERT (atomic_read (&desc->bd_source_callback_count) > 0 &&
                 atomic_read (&desc->bd_source_callback_count) <= 2);

        /* 1 fragment for each page always */
        LASSERT (ev->mem_desc.niov == desc->bd_page_count);

        if (atomic_dec_and_test (&desc->bd_source_callback_count)) {
                list_for_each_safe(tmp, next, &desc->bd_page_list) {
                        bulk = list_entry(tmp, struct ptlrpc_bulk_page,
                                          bp_link);

                        if (bulk->bp_cb != NULL)
                                bulk->bp_cb(bulk);
                }
                desc->bd_flags |= PTL_BULK_FL_SENT;
                wake_up(&desc->bd_waitq);
                if (desc->bd_cb != NULL)
                        desc->bd_cb(desc, desc->bd_cb_data);
        }

        RETURN(0);
}

static int bulk_sink_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_page *bulk;
        struct list_head        *tmp;
        struct list_head        *next;
        ptl_size_t               total = 0;
        ENTRY;

        if (ev->type == PTL_EVENT_PUT) {
                /* put with zero offset */
                LASSERT (ev->offset == 0);
                /* used iovs */
                LASSERT ((ev->mem_desc.options & PTL_MD_IOV) != 0);
                /* 1 fragment for each page always */
                LASSERT (ev->mem_desc.niov == desc->bd_page_count);

                list_for_each_safe (tmp, next, &desc->bd_page_list) {
                        bulk = list_entry(tmp, struct ptlrpc_bulk_page,
                                          bp_link);

                        total += bulk->bp_buflen;

                        if (bulk->bp_cb != NULL)
                                bulk->bp_cb(bulk);
                }

                LASSERT (ev->mem_desc.length == total);

                desc->bd_flags |= PTL_BULK_FL_RCVD;
                wake_up(&desc->bd_waitq);
                if (desc->bd_cb != NULL)
                        desc->bd_cb(desc, desc->bd_cb_data);
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
        gmnal_nip = inter_module_get_request("kgmnal_ni", "kgmnal");

        /* Use the qswnal if it's there */
        if (qswnal_nip != NULL)
                ni = *qswnal_nip;
        else if (gmnal_nip != NULL)
                ni = *gmnal_nip;
        else if (socknal_nip != NULL)
                ni = *socknal_nip;
        else {
                CERROR("get_ni failed: is a NAL module loaded?\n");
                return -EIO;
        }

        rc = PtlEQAlloc(ni, 1024, request_out_callback, &request_out_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 1024, reply_out_callback, &reply_out_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 1024, reply_in_callback, &reply_in_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 1024, bulk_source_callback, &bulk_source_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 1024, bulk_sink_callback, &bulk_sink_eq);
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
        if (gmnal_nip != NULL)
                inter_module_put("kgmnal_ni");
}
