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

ptl_handle_ni_t LUSTRE_NI;
static ptl_handle_eq_t req_eq;
static int req_initialized = 0;

/* This seems silly now, but some day we'll have more than one NI */
int req_get_peer(__u32 nid, struct lustre_peer *peer)
{
        peer->peer_ni = req_ni;
        peer->peer_nid = nid;

        return 0;
}
static int request_callback(ptl_event_t *ev, void *data)
{
        struct ptlrpc_request *rpc = ev->mem_desc.user_ptr;

        ENTRY;

        if (ev->type == PTL_EVENT_SENT) {
                kfree(rpc->rq_reqbuf);
        } else if (ev->type == PTL_EVENT_PUT) {
                struct ptlrpc_request *clnt_rpc = rpc->rq_reply_handle;

                rpc->rq_repbuf = ev->mem_desc.start + ev->offset;

                wake_up_interruptible(&clnt_rpc->rq_wait_for_rep);
        }

        EXIT;
        return 1;
}

int ptl_send_buf(struct ptlrpc_request *request, struct lustre_peer *peer,
                 int portal)
{
        int rc;
        ptl_process_id_t remote_id;
        ptl_handle_md_t md_h;

        request->rq_req_md.start = request->rq_reqbuf;
        request->rq_req_md.length = request->rq_reqlen;
        request->rq_req_md.threshold = PTL_MD_THRESH_INF;
        request->rq_req_md.options = PTL_MD_OP_PUT;
        request->rq_req_md.user_ptr = request;
        request->rq_req_md.eventq = PTL_EQ_NONE;

        rc = PtlMDBind(peer->peer_ni, request->rq_req_md, &md_h);
        if (rc != 0) {
                printk(__FUNCTION__ ": PtlMDBind failed: %d\n", rc);
                return rc;
        }

        remote_id.addr_kind = PTL_ADDR_NID;
        remote_id.nid = peer->peer_nid;
        remote_id.pid = 0;

        rc = PtlPut(md_h, PTL_NOACK_REQ, remote_id, portal, 0, 0, 0, 0);
        if (rc != PTL_OK) {
                printk(__FUNCTION__ ": PtlPut failed: %d\n", rc);
                /* FIXME: tear down md */
        }

        return rc;
}

int ptl_send_rpc(struct ptlrpc_request *request, struct lustre_peer *peer)
{
        ptl_handle_md_t reply_md_h;
        ptl_handle_me_t me_h;
        ptl_process_id_t local_id;
        int rc;

        ENTRY;

        request->rq_repbuf = kmalloc(request->rq_replen, GFP_KERNEL); 
        if (!request->rq_repbuf) { 
                EXIT;
                return -ENOMEM;
        }

        local_id.addr_kind = PTL_ADDR_GID;
        local_id.gid = PTL_ID_ANY;
        local_id.rid = PTL_ID_ANY;

        rc = PtlMEAttach(peer->peer_ni, request->rq_reply_portal, local_id,
                         0, ~0, PTL_RETAIN, &me_h);
        if (rc != PTL_OK) {
                EXIT;
                /* FIXME: tear down EQ, free reqbuf */
                return rc;
        }

        request->rq_reply_md.start = request->rq_repbuf;
        request->rq_reply_md.length = request->rq_replen;
        request->rq_reply_md.threshold = PTL_MD_THRESH_INF;
        request->rq_reply_md.options = PTL_MD_OP_PUT;
        request->rq_reply_md.user_ptr = request;
        request->rq_reply_md.eventq = req_eq;

        rc = PtlMDAttach(me_h, request->rq_reply_md, PTL_RETAIN, &reply_md_h);
        if (rc != PTL_OK) {
                EXIT;
                return rc;
        }

        return ptl_send_buf(request, peer, request->rq_req_portal);
}


//int req_init_event_queue(struct lustre_peer *peer);

static int req_init_portals(void)
{
        int rc;
        rc = PtlEQAlloc(req_ni, 128, request_callback, NULL, &req_eq);
        if (rc != PTL_OK) {
                EXIT;
                return rc; /* FIXME: does this portals rc make sense? */
        }

        return rc;
}

static int __init req_init(void)
{
        return req_init_portals();
}

static void __exit req_exit(void)
{
        if (req_initialized) {
                PtlNIFini(req_ni);
                inter_module_put(LUSTRE_NAL "_init");
        }
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor v1.0");
MODULE_LICENSE("GPL"); 

module_init(req_init);
module_exit(req_exit);
