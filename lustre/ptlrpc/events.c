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

ptl_handle_eq_t sent_pkt_eq, rcvd_rep_eq, bulk_source_eq, bulk_sink_eq;
static const ptl_handle_ni_t *socknal_nip = NULL, *qswnal_nip = NULL;

/*
 *  Free the packet when it has gone out
 */
static int sent_packet_callback(ptl_event_t *ev, void *data)
{
        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                OBD_FREE(ev->mem_desc.start, ev->mem_desc.length);
        } else { 
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type); 
                BUG();
        }

        EXIT;
        return 1;
}

/*
 * Wake up the thread waiting for the reply once it comes in.
 */
static int rcvd_reply_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_request *rpc = ev->mem_desc.user_ptr;
        ENTRY;

        if (ev->type == PTL_EVENT_PUT) {
                rpc->rq_repbuf = ev->mem_desc.start + ev->offset;
                barrier();
                wake_up_interruptible(&rpc->rq_wait_for_rep);
        } else { 
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type); 
                BUG();
        }

        EXIT;
        return 1;
}

int server_request_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_service *service = data;
        int rc;

        if (ev->rlength != ev->mlength)
                CERROR("Warning: Possibly truncated rpc (%d/%d)\n",
                       ev->mlength, ev->rlength);

        /* The ME is unlinked when there is less than 1024 bytes free
         * on its MD.  This ensures we are always able to handle the rpc, 
         * although the 1024 value is a guess as to the size of a
         * large rpc (the known safe margin should be determined).
         *
         * NOTE: The portals API by default unlinks all MD's associated
         *       with an ME when it's unlinked.  For now, this behavior
         *       has been commented out of the portals library so the
         *       MD can be unlinked when its ref count drops to zero.
         *       A new MD and ME will then be created that use the same
         *       kmalloc()'ed memory and inserted at the ring tail.
         */

        spin_lock(&service->srv_lock); 
        service->srv_ref_count[service->srv_md_active]++;

        CDEBUG(D_INODE, "event offset %d buf size %d\n", 
               ev->offset, service->srv_buf_size);
        if (ev->offset >= (service->srv_buf_size - 1024)) {
                CDEBUG(D_INODE, "Unlinking ME %d\n", service->srv_me_active);

                rc = PtlMEUnlink(service->srv_me_h[service->srv_me_active]);
                service->srv_me_h[service->srv_me_active] = 0;

                if (rc != PTL_OK) {
                        CERROR("PtlMEUnlink failed - DROPPING soon: %d\n", rc);
                        BUG();
                        spin_unlock(&service->srv_lock); 
                        return rc;
                }

                service->srv_me_active = NEXT_INDEX(service->srv_me_active,
                                                    service->srv_ring_length);

                if (service->srv_me_h[service->srv_me_active] == 0)
                        CERROR("All %d ring ME's are unlinked!\n",
                               service->srv_ring_length);
        }

        spin_unlock(&service->srv_lock); 
        if (ev->type == PTL_EVENT_PUT) {
                wake_up(&service->srv_waitq);
        } else {
                CERROR("Unexpected event type: %d\n", ev->type);
        }

        return 0;
}

static int bulk_source_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_bulk_desc *bulk = ev->mem_desc.user_ptr;

        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                CDEBUG(D_NET, "got SENT event\n");
        } else if (ev->type == PTL_EVENT_ACK) {
                CDEBUG(D_NET, "got ACK event\n");
                bulk->b_flags = PTL_BULK_SENT;
                wake_up_interruptible(&bulk->b_waitq);
        } else {
                CERROR("Unexpected event type!\n");
                BUG();
        }

        EXIT;
        return 1;
}

static int bulk_sink_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_bulk_desc *bulk = ev->mem_desc.user_ptr;

        ENTRY;

        if (ev->type == PTL_EVENT_PUT) {
                if (bulk->b_buf != ev->mem_desc.start + ev->offset)
                        CERROR("bulkbuf != mem_desc -- why?\n");
                bulk->b_flags = PTL_BULK_RCVD;
                if (bulk->b_cb != NULL)
                        bulk->b_cb(bulk, data);
                wake_up_interruptible(&bulk->b_waitq);
        } else {
                CERROR("Unexpected event type!\n");
                BUG();
        }

        /* FIXME: This should happen unconditionally */
        if (bulk->b_cb != NULL) {
                OBD_FREE(bulk, sizeof(*bulk));
        }

        EXIT;
        return 1;
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

        rc = PtlEQAlloc(ni, 128, sent_packet_callback, NULL, &sent_pkt_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, rcvd_reply_callback, NULL, &rcvd_rep_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, bulk_source_callback, NULL, &bulk_source_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, bulk_sink_callback, NULL, &bulk_sink_eq);
        if (rc != PTL_OK)
                CERROR("PtlEQAlloc failed: %d\n", rc);

        return rc;
}

void ptlrpc_exit_portals(void)
{
        PtlEQFree(sent_pkt_eq);
        PtlEQFree(rcvd_rep_eq);
        PtlEQFree(bulk_source_eq);
        PtlEQFree(bulk_sink_eq);

        if (qswnal_nip != NULL)
                inter_module_put("kqswnal_ni");
        if (socknal_nip != NULL)
                inter_module_put("ksocknal_ni");
}
