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

#include <linux/obd_support.h>
#include <linux/lustre_net.h>

static ptl_handle_eq_t req_eq, bulk_source_eq, bulk_sink_eq;

/* This callback performs two functions:
 *
 * 1. Free the request buffer after it has gone out on the wire
 * 2. Wake up the thread waiting for the reply once it comes in.
 */
static int request_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_request *rpc = ev->mem_desc.user_ptr;

        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                kfree(ev->mem_desc.start);
        } else if (ev->type == PTL_EVENT_PUT) {
                rpc->rq_repbuf = ev->mem_desc.start + ev->offset;
                wake_up_interruptible(&rpc->rq_wait_for_rep);
        }

        EXIT;
        return 1;
}

static int incoming_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_service *service = data;

        ENTRY;

        if (ev->type == PTL_EVENT_PUT) {
                wake_up(service->srv_wait_queue);
        } else {
                printk("Unexpected event type: %d\n", ev->type);
        }

        EXIT;
        return 0;
}

static int bulk_source_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_request *rpc = ev->mem_desc.user_ptr;

        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                ;
        } else if (ev->type == PTL_EVENT_ACK) {
                wake_up_interruptible(&rpc->rq_wait_for_bulk);
        } else {
                printk("Unexpected event type in " __FUNCTION__ "!\n");
        }

        EXIT;
        return 1;
}

static int bulk_sink_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_request *rpc = ev->mem_desc.user_ptr;

        ENTRY;

        if (ev->type == PTL_EVENT_PUT) {
                if (rpc->rq_bulkbuf != ev->mem_desc.start + ev->offset)
                        printk(__FUNCTION__ ": bulkbuf != mem_desc -- why?\n");
                wake_up_interruptible(&rpc->rq_wait_for_bulk);
        } else {
                printk("Unexpected event type in " __FUNCTION__ "!\n");
        }

        EXIT;
        return 1;
}

int ptl_send_buf(struct ptlrpc_request *request, struct lustre_peer *peer,
                 int portal, int is_request)
{
        int rc;
        ptl_process_id_t remote_id;
        ptl_handle_md_t md_h;

        /* FIXME: This is bad. */
        if (request->rq_bulklen) {
                request->rq_req_md.start = request->rq_bulkbuf;
                request->rq_req_md.length = request->rq_bulklen;
                request->rq_req_md.eventq = bulk_source_eq;
        } else if (is_request) {
                request->rq_req_md.start = request->rq_reqbuf;
                request->rq_req_md.length = request->rq_reqlen;
                request->rq_req_md.eventq = req_eq;
        } else {
                request->rq_req_md.start = request->rq_repbuf;
                request->rq_req_md.length = request->rq_replen;
                request->rq_req_md.eventq = req_eq;
        }
        request->rq_req_md.threshold = 1;
        request->rq_req_md.options = PTL_MD_OP_PUT;
        request->rq_req_md.user_ptr = request;

        rc = PtlMDBind(peer->peer_ni, request->rq_req_md, &md_h);
        if (rc != 0) {
                printk(__FUNCTION__ ": PtlMDBind failed: %d\n", rc);
                return rc;
        }

        remote_id.addr_kind = PTL_ADDR_NID;
        remote_id.nid = peer->peer_nid;
        remote_id.pid = 0;

        if (request->rq_bulklen) {
                rc = PtlPut(md_h, PTL_ACK_REQ, remote_id, portal, 0,
                            request->rq_xid, 0, 0);
        } else {
                rc = PtlPut(md_h, PTL_NOACK_REQ, remote_id, portal, 0,
                            request->rq_xid, 0, 0);
        }
        if (rc != PTL_OK) {
                printk(__FUNCTION__ ": PtlPut failed: %d\n", rc);
                /* FIXME: tear down md */
        }

        return rc;
}

int ptl_send_rpc(struct ptlrpc_request *request, struct lustre_peer *peer)
{
        ptl_handle_me_t me_h, bulk_me_h;
        ptl_process_id_t local_id;
        int rc;

        ENTRY;

        if (request->rq_replen == 0) {
                printk(__FUNCTION__ ": request->rq_replen is 0!\n");
                EXIT;
                return -EINVAL;
        }

        request->rq_repbuf = kmalloc(request->rq_replen, GFP_KERNEL); 
        if (!request->rq_repbuf) { 
                EXIT;
                return -ENOMEM;
        }

        local_id.addr_kind = PTL_ADDR_GID;
        local_id.gid = PTL_ID_ANY;
        local_id.rid = PTL_ID_ANY;

        rc = PtlMEAttach(peer->peer_ni, request->rq_reply_portal, local_id,
                         request->rq_xid, 0, PTL_UNLINK, &me_h);
        if (rc != PTL_OK) {
                EXIT;
                /* FIXME: tear down EQ, free reqbuf */
                return rc;
        }

        request->rq_reply_md.start = request->rq_repbuf;
        request->rq_reply_md.length = request->rq_replen;
        request->rq_reply_md.threshold = 1;
        request->rq_reply_md.options = PTL_MD_OP_PUT;
        request->rq_reply_md.user_ptr = request;
        request->rq_reply_md.eventq = req_eq;

        rc = PtlMDAttach(me_h, request->rq_reply_md, PTL_UNLINK,
                         &request->rq_reply_md_h);
        if (rc != PTL_OK) {
                EXIT;
                return rc;
        }

        if (request->rq_bulklen != 0) {
                rc = PtlMEAttach(peer->peer_ni, request->rq_bulk_portal,
                                 local_id, request->rq_xid, 0, PTL_UNLINK,
                                 &bulk_me_h);
                if (rc != PTL_OK) {
                        EXIT;
                        return rc;
                }

                request->rq_bulk_md.start = request->rq_bulkbuf;
                request->rq_bulk_md.length = request->rq_bulklen;
                request->rq_bulk_md.threshold = 1;
                request->rq_bulk_md.options = PTL_MD_OP_PUT;
                request->rq_bulk_md.user_ptr = request;
                request->rq_bulk_md.eventq = bulk_sink_eq;

                rc = PtlMDAttach(bulk_me_h, request->rq_bulk_md, PTL_UNLINK,
                                 &request->rq_bulk_md_h);
                if (rc != PTL_OK) {
                        EXIT;
                        return rc;
                }
        }

        return ptl_send_buf(request, peer, request->rq_req_portal, 1);
}

int rpc_register_service(struct ptlrpc_service *service, char *uuid)
{
        struct lustre_peer peer;
        int rc;

        rc = kportal_uuid_to_peer(uuid, &peer);
        if (rc != 0) {
                printk("Invalid uuid \"%s\"\n", uuid);
                return -EINVAL;
        }

        service->srv_buf = kmalloc(service->srv_buf_size, GFP_KERNEL);
        if (service->srv_buf == NULL) {
                printk(__FUNCTION__ ": no memory\n");
                return -ENOMEM;
        }

        service->srv_id.addr_kind = PTL_ADDR_GID;
        service->srv_id.gid = PTL_ID_ANY;
        service->srv_id.rid = PTL_ID_ANY;

	rc = PtlMEAttach(peer.peer_ni, service->srv_portal, service->srv_id,
                         0, ~0, PTL_RETAIN, &service->srv_me_h);
        if (rc != PTL_OK) {
                printk("PtlMEAttach failed: %d\n", rc);
                return rc;
        }

        rc = PtlEQAlloc(peer.peer_ni, 128, incoming_callback, service,
                        &service->srv_eq_h);
        if (rc != PTL_OK) {
                printk("PtlEQAlloc failed: %d\n", rc);
                return rc;
        }

        /* FIXME: Build an auto-unlinking MD and build a ring. */
        /* FIXME: Make sure that these are reachable by DMA on well-known
         * addresses. */
	service->srv_md.start		= service->srv_buf;
	service->srv_md.length		= service->srv_buf_size;
	service->srv_md.threshold	= PTL_MD_THRESH_INF;
	service->srv_md.options		= PTL_MD_OP_PUT;
	service->srv_md.user_ptr	= service;
	service->srv_md.eventq		= service->srv_eq_h;

	rc = PtlMDAttach(service->srv_me_h, service->srv_md,
                         PTL_RETAIN, &service->srv_md_h);
        if (rc != PTL_OK) {
                printk("PtlMDAttach failed: %d\n", rc);
                /* FIXME: wow, we need to clean up. */
                return rc;
        }

        return 0;
}

int rpc_unregister_service(struct ptlrpc_service *service)
{
        int rc;

        rc = PtlMDUnlink(service->srv_md_h);
        if (rc)
                printk(__FUNCTION__ ": PtlMDUnlink failed: %d\n", rc);
        rc = PtlEQFree(service->srv_eq_h);
        if (rc)
                printk(__FUNCTION__ ": PtlEQFree failed: %d\n", rc);
        rc = PtlMEUnlink(service->srv_me_h);
        if (rc)
                printk(__FUNCTION__ ": PtlMEUnlink failed: %d\n", rc);

        kfree(service->srv_buf);
        return 0;
}

static int req_init_portals(void)
{
        int rc;
        const ptl_handle_ni_t *nip;
        ptl_handle_ni_t ni;

        nip = inter_module_get_request(LUSTRE_NAL "_ni", LUSTRE_NAL);
        if (nip == NULL) {
                printk("get_ni failed: is the NAL module loaded?\n");
                return -EIO;
        }
        ni = *nip;

        rc = PtlEQAlloc(ni, 128, request_callback, NULL, &req_eq);
        if (rc != PTL_OK)
                printk("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, bulk_source_callback, NULL, &bulk_source_eq);
        if (rc != PTL_OK)
                printk("PtlEQAlloc failed: %d\n", rc);

        rc = PtlEQAlloc(ni, 128, bulk_sink_callback, NULL, &bulk_sink_eq);
        if (rc != PTL_OK)
                printk("PtlEQAlloc failed: %d\n", rc);

        return rc;
}

static int __init ptlrpc_init(void)
{
        return req_init_portals();
}

static void __exit ptlrpc_exit(void)
{
        PtlEQFree(req_eq);

        inter_module_put(LUSTRE_NAL "_ni");

        return;
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor v1.0");
MODULE_LICENSE("GPL"); 

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);

