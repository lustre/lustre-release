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

int ptlrpc_enqueue(struct ptlrpc_client *peer, struct ptlrpc_request *req)
{
	struct ptlrpc_request *srv_req;
	
	if (!peer->cli_obd) { 
		EXIT;
		return -1;
	}

	OBD_ALLOC(srv_req, sizeof(*srv_req));
	if (!srv_req) { 
		EXIT;
		return -ENOMEM;
	}

        CDEBUG(0, "peer obd minor %d, incoming req %p, srv_req %p\n",
	       peer->cli_obd->obd_minor, req, srv_req);

	memset(srv_req, 0, sizeof(*req)); 

	/* move the request buffer */
	srv_req->rq_reqbuf = req->rq_reqbuf;
	srv_req->rq_reqlen = req->rq_reqlen;
	srv_req->rq_obd = peer->cli_obd;

	/* remember where it came from */
	srv_req->rq_reply_handle = req;

	list_add(&srv_req->rq_list, &peer->cli_obd->obd_req_list); 
	wake_up(&peer->cli_obd->obd_req_waitq);
	return 0;
}

int ptlrpc_connect_client(int dev, char *uuid, int req_portal, int rep_portal, 
                          req_pack_t req_pack, rep_unpack_t rep_unpack,
                          struct ptlrpc_client *cl)
{
        int err; 

        memset(cl, 0, sizeof(*cl));
	cl->cli_xid = 1;
	cl->cli_obd = NULL; 
	cl->cli_request_portal = req_portal;
	cl->cli_reply_portal = rep_portal;
	cl->cli_rep_unpack = rep_unpack;
	cl->cli_req_pack = req_pack;

	/* non networked client */
	if (dev >= 0 && dev < MAX_OBD_DEVICES) {
		struct obd_device *obd = &obd_dev[dev];
		
		if ((!obd->obd_flags & OBD_ATTACHED) ||
		    (!obd->obd_flags & OBD_SET_UP)) { 
			CERROR("target device %d not att or setup\n", dev);
			return -EINVAL;
		}
                if (strcmp(obd->obd_type->typ_name, "ost") && 
                    strcmp(obd->obd_type->typ_name, "mds")) { 
                        return -EINVAL;
                }

		cl->cli_obd = &obd_dev[dev];
		return 0;
	}

	/* networked */
	err = kportal_uuid_to_peer(uuid, &cl->cli_server);
	if (err != 0) { 
		CERROR("cannot find peer %s!", uuid); 
	}

        return err;
}

struct ptlrpc_request *ptlrpc_prep_req(struct ptlrpc_client *cl, 
                                       int opcode, int namelen, char *name,
                                       int tgtlen, char *tgt)
{
	struct ptlrpc_request *request;
	int rc;
	ENTRY; 

	OBD_ALLOC(request, sizeof(*request));
	if (!request) { 
		CERROR("request allocation out of memory\n");
		return NULL;
	}

	memset(request, 0, sizeof(*request));
	request->rq_xid = cl->cli_xid++;

	rc = cl->cli_req_pack(name, namelen, tgt, tgtlen,
			  &request->rq_reqhdr, &request->rq_req,
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		CERROR("cannot pack request %d\n", rc); 
		return NULL;
	}
	request->rq_reqhdr->opc = opcode;
	request->rq_reqhdr->xid = request->rq_xid;

	EXIT;
	return request;
}

void ptlrpc_free_req(struct ptlrpc_request *request)
{
	OBD_FREE(request, sizeof(*request));
}

static int ptlrpc_check_reply(struct ptlrpc_request *req)
{
        if (req->rq_repbuf != NULL) {
                req->rq_flags = PTL_RPC_REPLY;
                EXIT;
                return 1;
        }

        if (sigismember(&(current->pending.signal), SIGKILL) ||
            sigismember(&(current->pending.signal), SIGINT)) { 
                req->rq_flags = PTL_RPC_INTR;
                EXIT;
                return 1;
        }

        CERROR("no event yet\n"); 
        return 0;
}

/* Abort this request and cleanup any resources associated with it. */
int ptlrpc_abort(struct ptlrpc_request *request)
{
        /* First remove the MD for the reply; in theory, this means
         * that we can tear down the buffer safely. */
        PtlMEUnlink(request->rq_reply_me_h);
        PtlMDUnlink(request->rq_reply_md_h);
        OBD_FREE(request->rq_repbuf, request->rq_replen);
        request->rq_repbuf = NULL;
        request->rq_replen = 0;

        if (request->rq_bulklen != 0) {
                PtlMEUnlink(request->rq_bulk_me_h);
                PtlMDUnlink(request->rq_bulk_md_h);
                /* FIXME: wake whoever's sleeping on this bulk sending to let
                 * -them- clean it up. */
        }

        return 0;
}

int ptlrpc_queue_wait(struct ptlrpc_client *cl, struct ptlrpc_request *req)
                             
{
	int rc;
        ENTRY;

	init_waitqueue_head(&req->rq_wait_for_rep);

	if (cl->cli_obd) {
		/* Local delivery */
                ENTRY;
		rc = ptlrpc_enqueue(cl, req); 
	} else {
		/* Remote delivery via portals. */
		req->rq_req_portal = cl->cli_request_portal;
		req->rq_reply_portal = cl->cli_reply_portal;
		rc = ptl_send_rpc(req, &cl->cli_server);
	}
	if (rc) { 
		CERROR("error %d, opcode %d\n", rc, 
		       req->rq_reqhdr->opc); 
		return -rc;
	}

        CDEBUG(0, "-- sleeping\n");
        wait_event_interruptible(req->rq_wait_for_rep, 
                                 ptlrpc_check_reply(req));
        CDEBUG(0, "-- done\n");
        
        if (req->rq_flags == PTL_RPC_INTR) { 
                /* Clean up the dangling reply buffers */
                ptlrpc_abort(req);
                EXIT;
                return -EINTR;
        }

        if (req->rq_flags != PTL_RPC_REPLY) { 
                CERROR("Unknown reason for wakeup\n");
                EXIT;
                return -EINTR;
        }

	rc = cl->cli_rep_unpack(req->rq_repbuf, req->rq_replen, &req->rq_rephdr, &req->rq_rep);
	if (rc) {
		CERROR("unpack_rep failed: %d\n", rc);
		return rc;
	}
        CERROR("got rep %d\n", req->rq_rephdr->xid);

	if ( req->rq_rephdr->status == 0 )
                CDEBUG(0, "--> buf %p len %d status %d\n",
		       req->rq_repbuf, req->rq_replen, 
		       req->rq_rephdr->status); 

	EXIT;
	return 0;
}
