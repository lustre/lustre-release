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
int obd_debug_level;
int obd_print_entry;

/*
 * 1. Free the request buffer after it has gone out on the wire
 * 2. Wake up the thread waiting for the reply once it comes in.
 */
static int request_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_request *rpc = ev->mem_desc.user_ptr;

        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                OBD_FREE(ev->mem_desc.start, ev->mem_desc.length);
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
	int rc;

	if (ev->rlength != ev->mlength)
		printk("Warning: Possibly truncated rpc (%d/%d)\n",
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

	service->srv_ref_count[service->srv_md_active]++;

	if (ev->offset >= (service->srv_buf_size - 1024)) {
		printk("Unlinking ME %d\n", service->srv_me_active);

		rc = PtlMEUnlink(service->srv_me_h[service->srv_me_active]);
		service->srv_me_h[service->srv_me_active] = 0;

		if (rc != PTL_OK) {
			printk("PtlMEUnlink failed: %d\n", rc);	
			return rc;
		}

		service->srv_me_active = NEXT_INDEX(service->srv_me_active,
			service->srv_ring_length);

		if (service->srv_me_h[service->srv_me_active] == 0)
			printk("All %d ring ME's are unlinked!\n",
				service->srv_ring_length);

	}

        if (ev->type == PTL_EVENT_PUT) {
                wake_up(service->srv_wait_queue);
        } else {
                printk("Unexpected event type: %d\n", ev->type);
        }

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

        OBD_ALLOC(request->rq_repbuf, request->rq_replen);
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

/* ptl_received_rpc() should be called by the sleeping process once
 * it finishes processing an event.  This ensures the ref count is
 * decremented and that the rpc ring buffer cycles properly.
 */ 
int ptl_received_rpc(struct ptlrpc_service *service) {
	int rc, index;

	index = service->srv_md_active;
	CDEBUG(D_INFO, "MD index=%d Ref Count=%d\n", index,
        	service->srv_ref_count[index]);
	service->srv_ref_count[index]--;

	if ((service->srv_ref_count[index] <= 0) &&
	    (service->srv_me_h[index] == 0)) {

		rc = PtlMDUnlink(service->srv_md_h[index]);
		CDEBUG(D_INFO, "Removing MD at index %d, rc %d\n", index, rc);

                if (rc)
                        printk(__FUNCTION__ 
                               ": PtlMDUnlink failed: index %d rc %d\n", 
                               index, rc);

                /* Replace the unlinked ME and MD */

                rc = PtlMEInsert(service->srv_me_h[service->srv_me_tail],
                        service->srv_id, 0, ~0, PTL_RETAIN,
                        PTL_INS_AFTER, &(service->srv_me_h[index]));
		CDEBUG(D_INFO, "Inserting new ME and MD in ring, rc %d\n", rc);
		service->srv_me_tail = index;
                service->srv_ref_count[index] = 0;
                
		if (rc != PTL_OK) {
                        printk("PtlMEInsert failed: %d\n", rc);
                        return rc;
                }

                service->srv_md[index].start        = service->srv_buf[index];
                service->srv_md[index].length       = service->srv_buf_size;
                service->srv_md[index].threshold    = PTL_MD_THRESH_INF;
                service->srv_md[index].options      = PTL_MD_OP_PUT;
                service->srv_md[index].user_ptr     = service;
                service->srv_md[index].eventq       = service->srv_eq_h;

                rc = PtlMDAttach(service->srv_me_h[index], service->srv_md[index],
                        PTL_RETAIN, &(service->srv_md_h[index]));

		CDEBUG(D_INFO, "Attach MD in ring, rc %d\n", rc);
                if (rc != PTL_OK) {
                        /* cleanup */
                        printk("PtlMDAttach failed: %d\n", rc);
                        return rc;
                }

		service->srv_md_active = NEXT_INDEX(index,
			service->srv_ring_length);
	} 
	
	return 0;
}

int rpc_register_service(struct ptlrpc_service *service, char *uuid)
{
        struct lustre_peer peer;
        int rc, i;

        rc = kportal_uuid_to_peer(uuid, &peer);
        if (rc != 0) {
                printk("Invalid uuid \"%s\"\n", uuid);
                return -EINVAL;
        }

        service->srv_ring_length = RPC_RING_LENGTH;
	service->srv_me_active = 0;
	service->srv_md_active = 0;

        service->srv_id.addr_kind = PTL_ADDR_GID;
        service->srv_id.gid = PTL_ID_ANY;
        service->srv_id.rid = PTL_ID_ANY;

        rc = PtlEQAlloc(peer.peer_ni, 128, incoming_callback,
                service, &(service->srv_eq_h));

        if (rc != PTL_OK) {
                printk("PtlEQAlloc failed: %d\n", rc);
                return rc;
        }

        /* Attach the leading ME on which we build the ring */
        rc = PtlMEAttach(peer.peer_ni, service->srv_portal,
                service->srv_id, 0, ~0, PTL_RETAIN,
                &(service->srv_me_h[0]));

        if (rc != PTL_OK) {
                printk("PtlMEAttach failed: %d\n", rc);
                return rc;
        }

        for (i = 0; i < service->srv_ring_length; i++) {
		OBD_ALLOC(service->srv_buf[i], service->srv_buf_size);                

                if (service->srv_buf[i] == NULL) {
                        printk(__FUNCTION__ ": no memory\n");
                        return -ENOMEM;
                }

                /* Insert additional ME's to the ring */
                if (i > 0) {
			rc = PtlMEInsert(service->srv_me_h[i-1],
				service->srv_id, 0, ~0, PTL_RETAIN,
				PTL_INS_AFTER, &(service->srv_me_h[i]));
			service->srv_me_tail = i;

	                if (rc != PTL_OK) {
	                        printk("PtlMEInsert failed: %d\n", rc);
	                        return rc;
	                }
		}

                service->srv_ref_count[i] = 0;
                service->srv_md[i].start	= service->srv_buf[i];
                service->srv_md[i].length	= service->srv_buf_size;
                service->srv_md[i].threshold	= PTL_MD_THRESH_INF;
                service->srv_md[i].options	= PTL_MD_OP_PUT;
                service->srv_md[i].user_ptr	= service;
                service->srv_md[i].eventq	= service->srv_eq_h;

                rc = PtlMDAttach(service->srv_me_h[i], service->srv_md[i],
                        PTL_RETAIN, &(service->srv_md_h[i]));

                if (rc != PTL_OK) {
                        /* cleanup */
                        printk("PtlMDAttach failed: %d\n", rc);
                        return rc;
                }
	}

        return 0;
}

int rpc_unregister_service(struct ptlrpc_service *service)
{
        int rc, i;

	for (i = 0; i < service->srv_ring_length; i++) {
	        rc = PtlMDUnlink(service->srv_md_h[i]);
	        if (rc)
	                printk(__FUNCTION__ ": PtlMDUnlink failed: %d\n", rc);
	
		rc = PtlMEUnlink(service->srv_me_h[i]);
	        if (rc)
	                printk(__FUNCTION__ ": PtlMEUnlink failed: %d\n", rc);
	
		OBD_FREE(service->srv_buf[i], service->srv_buf_size);		
	}

        rc = PtlEQFree(service->srv_eq_h);
        if (rc)
                printk(__FUNCTION__ ": PtlEQFree failed: %d\n", rc);

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
        PtlEQFree(bulk_source_eq);
        PtlEQFree(bulk_sink_eq);

        inter_module_put(LUSTRE_NAL "_ni");

        return;
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor v1.0");
MODULE_LICENSE("GPL"); 

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);
