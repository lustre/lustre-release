/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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
 *  Storage Target Handling functions
 *  Lustre Object Server Module (OST)
 *
 *  This server is single threaded at present (but can easily be multi
 *  threaded). For testing and management it is treated as an
 *  obd_device, although it does not export a full OBD method table
 *  (the requests are coming in over the wire, so object target
 *  modules do not have a full method table.)
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/ext2_fs.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_OST

#include <linux/obd_support.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>

// for testing
static int ost_queue_req(struct obd_device *obddev, struct ptlrpc_request *req)
{
	struct ptlrpc_request *srv_req; 
	struct ost_obd *ost = &obddev->u.ost;
	
	if (!ost) { 
		EXIT;
		return -1;
	}

	OBD_ALLOC(srv_req, sizeof(*srv_req));
	if (!srv_req) { 
		EXIT;
		return -ENOMEM;
	}

        CDEBUG(0, "---> OST at %d %p, incoming req %p, srv_req %p\n",
	       __LINE__, ost, req, srv_req);

	memset(srv_req, 0, sizeof(*req)); 

	/* move the request buffer */
	srv_req->rq_reqbuf = req->rq_reqbuf;
	srv_req->rq_reqlen    = req->rq_reqlen;
	srv_req->rq_ost = ost;

	/* remember where it came from */
	srv_req->rq_reply_handle = req;

        spin_lock(&ost->ost_lock);
	list_add(&srv_req->rq_list, &ost->ost_reqs); 
        spin_unlock(&ost->ost_lock);
	wake_up(&ost->ost_waitq);
	return 0;
}

int ost_reply(struct obd_device *obddev, struct ptlrpc_request *req)
{
	struct ptlrpc_request *clnt_req = req->rq_reply_handle;

	ENTRY;

	if (req->rq_ost->ost_service != NULL) {
		/* This is a request that came from the network via portals. */

		/* FIXME: we need to increment the count of handled events */
		ptl_send_buf(req, &req->rq_peer, OST_REPLY_PORTAL, 0);
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

int ost_error(struct obd_device *obddev, struct ptlrpc_request *req)
{
	struct ptlrep_hdr *hdr;

	ENTRY;

	OBD_ALLOC(hdr, sizeof(*hdr));
	if (!hdr) { 
		EXIT;
		return -ENOMEM;
	}

	memset(hdr, 0, sizeof(*hdr));
	
	hdr->seqno = req->rq_reqhdr->seqno;
	hdr->status = req->rq_status; 
	hdr->type = OST_TYPE_ERR;

	req->rq_repbuf = (char *)hdr;
	req->rq_replen = sizeof(*hdr); 

	EXIT;
	return ost_reply(obddev, req);
}

static int ost_destroy(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_destroy
		(&conn, &req->rq_req.ost->oa); 

	EXIT;
	return 0;
}

static int ost_getattr(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}
	req->rq_rep.ost->oa.o_id = req->rq_req.ost->oa.o_id;
	req->rq_rep.ost->oa.o_valid = req->rq_req.ost->oa.o_valid;

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_getattr
		(&conn, &req->rq_rep.ost->oa); 

	EXIT;
	return 0;
}

static int ost_create(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep.ost->oa, &req->rq_req.ost->oa, sizeof(req->rq_req.ost->oa));

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_create
		(&conn, &req->rq_rep.ost->oa); 

	EXIT;
	return 0;
}

static int ost_punch(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep.ost->oa, &req->rq_req.ost->oa, sizeof(req->rq_req.ost->oa));

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_punch
		(&conn, &req->rq_rep.ost->oa, 
		 req->rq_rep.ost->oa.o_size,
		 req->rq_rep.ost->oa.o_blocks); 

	EXIT;
	return 0;
}


static int ost_setattr(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}

	memcpy(&req->rq_rep.ost->oa, &req->rq_req.ost->oa,
	       sizeof(req->rq_req.ost->oa));

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_setattr
		(&conn, &req->rq_rep.ost->oa); 

	EXIT;
	return 0;
}

static int ost_connect(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_dev = ost->ost_tgt;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_connect(&conn);

        CDEBUG(0, "rep buffer %p, id %d\n", req->rq_repbuf,
	       conn.oc_id);
	req->rq_rep.ost->connid = conn.oc_id;
	EXIT;
	return 0;
}

static int ost_disconnect(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;

	ENTRY;
	
	conn.oc_dev = ost->ost_tgt;
	conn.oc_id = req->rq_req.ost->connid;

	rc = ost_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}

	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_disconnect(&conn);

	EXIT;
	return 0;
}

static int ost_get_info(struct ost_obd *ost, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;
	int vallen;
	void *val;
	char *ptr; 

	ENTRY;
	
	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = ost->ost_tgt;

	ptr = ost_req_buf1(req->rq_req.ost);
	req->rq_rep.ost->result =ost->ost_tgt->obd_type->typ_ops->o_get_info
		(&conn, req->rq_req.ost->buflen1, ptr, &vallen, &val); 

	rc = ost_pack_rep(val, vallen, NULL, 0, &req->rq_rephdr,
                          &req->rq_rep.ost, &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}

	EXIT;
	return 0;
}

int ost_brw(struct ost_obd *obddev, struct ptlrpc_request *req)
{
	struct obd_conn conn; 
	int rc;
	int i, j;
	int objcount, niocount;
	char *tmp1, *tmp2, *end2;
	char *res;
	int cmd;
	struct niobuf *nb, *src, *dst;
	struct obd_ioobj *ioo;
	struct ost_req *r = req->rq_req.ost;

	ENTRY;
	
	tmp1 = ost_req_buf1(r);
	tmp2 = ost_req_buf2(r);
	end2 = tmp2 + req->rq_req.ost->buflen2;
	objcount = r->buflen1 / sizeof(*ioo); 
	niocount = r->buflen2 / sizeof(*nb); 
	cmd = r->cmd;

	conn.oc_id = req->rq_req.ost->connid;
	conn.oc_dev = req->rq_ost->ost_tgt;

	rc = ost_pack_rep(NULL, niocount, NULL, 0, 
			  &req->rq_rephdr, &req->rq_rep.ost,
			  &req->rq_replen, &req->rq_repbuf); 
	if (rc) { 
		CERROR("cannot pack reply\n"); 
		return rc;
	}
	res = ost_rep_buf1(req->rq_rep.ost); 

	for (i=0; i < objcount; i++) { 
		ost_unpack_ioo((void *)&tmp1, &ioo);
		if (tmp2 + ioo->ioo_bufcnt > end2) { 
			rc = -EFAULT;
			break; 
		}
		for (j = 0 ; j < ioo->ioo_bufcnt ; j++) { 
			ost_unpack_niobuf((void *)&tmp2, &nb); 
		}
	}

	/* The unpackers move tmp1 and tmp2, so reset them before using */
	tmp1 = ost_req_buf1(r);
	tmp2 = ost_req_buf2(r);
	req->rq_rep.ost->result = 
		req->rq_ost->ost_tgt->obd_type->typ_ops->o_preprw
		(cmd, &conn, objcount, (struct obd_ioobj *)tmp1, 
		 niocount, (struct niobuf *)tmp2, (struct niobuf *)res); 

	if (req->rq_rep.ost->result) {
		EXIT;
		goto out;
	}

        if (cmd == OBD_BRW_WRITE) {
                for (i = 0; i < niocount; i++) {
			src = &((struct niobuf *)tmp2)[i];
			dst = &((struct niobuf *)res)[i];
			memcpy((void *)(unsigned long)dst->addr, 
			       (void *)(unsigned long)src->addr, 
			       src->len);
		}
		barrier();
	} else { 
                for (i = 0; i < niocount; i++) {
			dst = &((struct niobuf *)tmp2)[i];
			src = &((struct niobuf *)res)[i];
			memcpy((void *)(unsigned long)dst->addr, 
			       (void *)(unsigned long)src->addr, 
			       PAGE_SIZE); 
		}
		barrier();
	}

	req->rq_rep.ost->result = 
		req->rq_ost->ost_tgt->obd_type->typ_ops->o_commitrw
		(cmd, &conn, objcount, (struct obd_ioobj *)tmp1, 
		 niocount, (struct niobuf *)res); 

 out:
	EXIT;
	return 0;
}

int ost_handle(struct obd_device *obddev, struct ptlrpc_request *req)
{
	int rc;
	struct ost_obd *ost = &obddev->u.ost;
	struct ptlreq_hdr *hdr;

	ENTRY;
        CDEBUG(0, "req at %p\n", req);

	hdr = (struct ptlreq_hdr *)req->rq_reqbuf;
	if (NTOH__u32(hdr->type) != OST_TYPE_REQ) {
		CERROR("lustre_ost: wrong packet type sent %d\n",
		       NTOH__u32(hdr->type));
		rc = -EINVAL;
		goto out;
	}

	rc = ost_unpack_req(req->rq_reqbuf, req->rq_reqlen, 
			    &req->rq_reqhdr, &req->rq_req.ost);
	if (rc) { 
		CERROR("lustre_ost: Invalid request\n");
		EXIT; 
		goto out;
	}

	switch (req->rq_reqhdr->opc) { 

	case OST_CONNECT:
		CDEBUG(D_INODE, "connect\n");
		rc = ost_connect(ost, req);
		break;
	case OST_DISCONNECT:
		CDEBUG(D_INODE, "disconnect\n");
		rc = ost_disconnect(ost, req);
		break;
	case OST_GET_INFO:
		CDEBUG(D_INODE, "get_info\n");
		rc = ost_get_info(ost, req);
		break;
	case OST_CREATE:
		CDEBUG(D_INODE, "create\n");
		rc = ost_create(ost, req);
		break;
	case OST_DESTROY:
		CDEBUG(D_INODE, "destroy\n");
		rc = ost_destroy(ost, req);
		break;
	case OST_GETATTR:
		CDEBUG(D_INODE, "getattr\n");
		rc = ost_getattr(ost, req);
		break;
	case OST_SETATTR:
		CDEBUG(D_INODE, "setattr\n");
		rc = ost_setattr(ost, req);
		break;
	case OST_BRW:
		CDEBUG(D_INODE, "brw\n");
		rc = ost_brw(ost, req);
		break;
	case OST_PUNCH:
		CDEBUG(D_INODE, "punch\n");
		rc = ost_punch(ost, req);
		break;
	default:
		req->rq_status = -ENOTSUPP;
		return ost_error(obddev, req);
	}

out:
	req->rq_status = rc;
	if (rc) { 
		CERROR("ost: processing error %d\n", rc);
		ost_error(obddev, req);
	} else { 
		CDEBUG(D_INODE, "sending reply\n"); 
		ost_reply(obddev, req); 
	}

	return 0;
}

/* FIXME: Serious refactoring needed */
int ost_main(void *arg)
{
        int signal; 
	struct obd_device *obddev = (struct obd_device *) arg;
	struct ost_obd *ost = &obddev->u.ost;
        DECLARE_WAITQUEUE(wait, current);

	ENTRY;

	lock_kernel();
	daemonize();
	spin_lock_irq(&current->sigmask_lock);
	sigfillset(&current->blocked);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);

	sprintf(current->comm, "lustre_ost");

	/* Record that the  thread is running */
	ost->ost_thread = current;
	wake_up(&ost->ost_done_waitq); 

	/* XXX maintain a list of all managed devices: insert here */

	/* And now, wait forever for commit wakeup events. */
	while (1) {
		int rc; 

		if (ost->ost_service != NULL) {
			ptl_event_t ev;
                        struct ptlrpc_request request;
                        struct ptlrpc_service *service;

                        CDEBUG(D_IOCTL, "-- sleeping\n");
                        signal = 0;
                        add_wait_queue(&ost->ost_waitq, &wait);
                        while (1) {
                                set_current_state(TASK_INTERRUPTIBLE);
                                rc = PtlEQGet(ost->ost_service->srv_eq_h, &ev);
                                if (rc == PTL_OK || rc == PTL_EQ_DROPPED)
                                        break;
                                if (ost->ost_flags & OST_EXIT)
                                        break;


                                /* if this process really wants to die,
                                 * let it go */
                                if (sigismember(&(current->pending.signal),
                                                SIGKILL) ||
                                    sigismember(&(current->pending.signal),
                                                SIGINT)) {
                                        signal = 1;
                                        break;
                                }

                                schedule();
                        }
                        remove_wait_queue(&ost->ost_waitq, &wait);
                        set_current_state(TASK_RUNNING);
                        CDEBUG(D_IOCTL, "-- done\n");

                        if (signal == 1) {
                                /* We broke out because of a signal */
                                EXIT;
                                break;
                        }
                        if (ost->ost_flags & OST_EXIT) {
                                EXIT;
                                break;
                        }

                        service = (struct ptlrpc_service *)ev.mem_desc.user_ptr;

                        /* FIXME: If we move to an event-driven model,
                         * we should put the request on the stack of
                         * mds_handle instead. */
                        memset(&request, 0, sizeof(request));
                        request.rq_reqbuf = ev.mem_desc.start + ev.offset;
                        request.rq_reqlen = ev.mem_desc.length;
                        request.rq_ost = ost;
                        request.rq_xid = ev.match_bits;

                        request.rq_peer.peer_nid = ev.initiator.nid;
                        /* FIXME: this NI should be the incoming NI.
                         * We don't know how to find that from here. */
                        request.rq_peer.peer_ni =
                                ost->ost_service->srv_self.peer_ni;
                        rc = ost_handle(obddev, &request);

                        /* Inform the rpc layer the event has been handled */
                        ptl_received_rpc(service);
		} else {
			struct ptlrpc_request *request;

                        CDEBUG(D_IOCTL, "-- sleeping\n");
                        add_wait_queue(&ost->ost_waitq, &wait);
                        while (1) {
                                spin_lock(&ost->ost_lock);
                                if (!list_empty(&ost->ost_reqs))
                                        break;

                                set_current_state(TASK_INTERRUPTIBLE);

                                /* if this process really wants to die,
                                 * let it go */
                                if (sigismember(&(current->pending.signal),
                                                SIGKILL) ||
                                    sigismember(&(current->pending.signal),
                                                SIGINT))
                                        break;

                                spin_unlock(&ost->ost_lock);

                                schedule();
                        }
                        remove_wait_queue(&ost->ost_waitq, &wait);
                        set_current_state(TASK_RUNNING);
                        CDEBUG(D_IOCTL, "-- done\n");

			if (list_empty(&ost->ost_reqs)) { 
				CDEBUG(D_INODE, "woke because of signal\n");
                                spin_unlock(&ost->ost_lock);
			} else {
				request = list_entry(ost->ost_reqs.next,
						     struct ptlrpc_request,
						     rq_list);
				list_del(&request->rq_list);
                                spin_unlock(&ost->ost_lock);
				rc = ost_handle(obddev, request); 
			}
		}
	}

	/* XXX maintain a list of all managed devices: cleanup here */

	ost->ost_thread = NULL;
	wake_up(&ost->ost_done_waitq);
	CERROR("lustre_ost: exiting\n");
	return 0;
}

static void ost_stop_srv_thread(struct ost_obd *ost)
{
	ost->ost_flags |= OST_EXIT;

	while (ost->ost_thread) {
		wake_up(&ost->ost_waitq);
		sleep_on(&ost->ost_done_waitq);
	}
}

static void ost_start_srv_thread(struct obd_device *obd)
{
	struct ost_obd *ost = &obd->u.ost;
	ENTRY;

	init_waitqueue_head(&ost->ost_waitq);
	init_waitqueue_head(&ost->ost_done_waitq);
	kernel_thread(ost_main, (void *)obd, 
		      CLONE_VM | CLONE_FS | CLONE_FILES);
	while (!ost->ost_thread) 
		sleep_on(&ost->ost_done_waitq);
	EXIT;
}

/* mount the file system (secretly) */
static int ost_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct ost_obd *ost = &obddev->u.ost;
	struct obd_device *tgt;
	struct lustre_peer peer;
	int err; 
        ENTRY;

	if (data->ioc_dev  < 0 || data->ioc_dev > MAX_OBD_DEVICES) { 
		EXIT;
		return -ENODEV;
	}

        tgt = &obd_dev[data->ioc_dev];
	ost->ost_tgt = tgt;
        if ( ! (tgt->obd_flags & OBD_ATTACHED) || 
             ! (tgt->obd_flags & OBD_SET_UP) ){
                CERROR("device not attached or not set up (%d)\n", 
                       data->ioc_dev);
                EXIT;
		return -EINVAL;
        } 

	ost->ost_conn.oc_dev = tgt;
	err = tgt->obd_type->typ_ops->o_connect(&ost->ost_conn);
	if (err) { 
		CERROR("lustre ost: fail to connect to device %d\n", 
		       data->ioc_dev); 
		return -EINVAL;
	}

	INIT_LIST_HEAD(&ost->ost_reqs);
	ost->ost_thread = NULL;
	ost->ost_flags = 0;

	spin_lock_init(&obddev->u.ost.ost_lock);

	err = kportal_uuid_to_peer("self", &peer);
	if (err == 0) {
		OBD_ALLOC(ost->ost_service, sizeof(*ost->ost_service));
		if (ost->ost_service == NULL)
			return -ENOMEM;
		ost->ost_service->srv_buf_size = 64 * 1024;
		ost->ost_service->srv_portal = OST_REQUEST_PORTAL;
		memcpy(&ost->ost_service->srv_self, &peer, sizeof(peer));
		ost->ost_service->srv_wait_queue = &ost->ost_waitq;

		rpc_register_service(ost->ost_service, "self");
	}

	ost_start_srv_thread(obddev);

        MOD_INC_USE_COUNT;
        EXIT; 
        return 0;
} 

static int ost_cleanup(struct obd_device * obddev)
{
	struct ost_obd *ost = &obddev->u.ost;
	struct obd_device *tgt;
	int err;

        ENTRY;

        if ( !(obddev->obd_flags & OBD_SET_UP) ) {
                EXIT;
                return 0;
        }

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                CERROR("still has clients!\n");
                EXIT;
                return -EBUSY;
        }

	ost_stop_srv_thread(ost);
	rpc_unregister_service(ost->ost_service);
        OBD_FREE(ost->ost_service, sizeof(*ost->ost_service));

	if (!list_empty(&ost->ost_reqs)) {
		// XXX reply with errors and clean up
		CDEBUG(D_INODE, "Request list not empty!\n");
	}

	tgt = ost->ost_tgt;
	err = tgt->obd_type->typ_ops->o_disconnect(&ost->ost_conn);
	if (err) { 
		CERROR("lustre ost: fail to disconnect device\n");
		return -EINVAL;
	}
	

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
}

/* use obd ops to offer management infrastructure */
static struct obd_ops ost_obd_ops = {
        o_setup:       ost_setup,
        o_cleanup:     ost_cleanup,
};

static int __init ost_init(void)
{
        obd_register_type(&ost_obd_ops, LUSTRE_OST_NAME);
	return 0;
}

static void __exit ost_exit(void)
{
	obd_unregister_type(LUSTRE_OST_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST) v0.01");
MODULE_LICENSE("GPL");

// for testing (maybe this stays)
EXPORT_SYMBOL(ost_queue_req);

module_init(ost_init);
module_exit(ost_exit);
