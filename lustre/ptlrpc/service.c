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

extern int server_request_callback(ptl_event_t *ev, void *data);

static int ptlrpc_check_event(struct ptlrpc_service *svc)
{
        
        if (sigismember(&(current->pending.signal),
                        SIGKILL) ||
            sigismember(&(current->pending.signal),
                        SIGINT)) { 
                svc->srv_flags |= SVC_KILLED;
                EXIT;
                return 1;
        }

        if ( svc->srv_flags & SVC_STOPPING ) {
                EXIT;
                return 1;
        }

        if ( svc->srv_eq_h ) { 
                int rc;
                rc = PtlEQGet(svc->srv_eq_h, &svc->srv_ev);

                if (rc == PTL_OK) { 
                        svc->srv_flags |= SVC_EVENT;
                        EXIT;
                        return 1;
                }

                if (rc == PTL_EQ_DROPPED) { 
                        CERROR("dropped event!\n");
                        BUG();
                }
                CERROR("PtlEQGet returns %d\n", rc); 
                EXIT;
                return 0;
        }

        if (!list_empty(&svc->srv_reqs)) {
                svc->srv_flags |= SVC_LIST;
                EXIT;
                return 1;
        }
                
        EXIT;
        return 0;
}

struct ptlrpc_service *ptlrpc_init_svc(__u32 bufsize, 
                                       int req_portal, 
                                       int rep_portal, 
                                       char *uuid, 
                                       req_unpack_t unpack, 
                                       rep_pack_t pack,
                                       svc_handler_t handler
                                       )
{
        int err;
        struct ptlrpc_service *svc;

        OBD_ALLOC(svc, sizeof(*svc)); 
        if ( !svc ) { 
                CERROR("no memory\n");
                return NULL;
        }

        memset(svc, 0, sizeof(*svc)); 

        spin_lock_init(&svc->srv_lock);
        INIT_LIST_HEAD(&svc->srv_reqs);
        init_waitqueue_head(&svc->srv_ctl_waitq); 
        init_waitqueue_head(&svc->srv_waitq); 

        svc->srv_thread = NULL;
	svc->srv_flags = 0;

        svc->srv_buf_size = bufsize;
        svc->srv_rep_portal = rep_portal;
        svc->srv_req_portal = req_portal;
        svc->srv_req_unpack = unpack;
        svc->srv_rep_pack = pack;
        svc->srv_handler = handler;
	err = kportal_uuid_to_peer(uuid, &svc->srv_self);
        if (err) { 
                CERROR("cannot get peer for uuid %s", uuid); 
                OBD_FREE(svc, sizeof(*svc));
                return NULL; 
        }
        return svc;
}

static int ptlrpc_main(void *arg)
{
        int rc;
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
	struct obd_device *obddev = data->dev;
        struct ptlrpc_service *svc = data->svc;

	ENTRY;

	lock_kernel();
	daemonize();
	spin_lock_irq(&current->sigmask_lock);
	sigfillset(&current->blocked);
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);

	sprintf(current->comm, data->name);

	/* Record that the  thread is running */
	svc->srv_thread = current;
        svc->srv_flags = SVC_RUNNING;
	wake_up(&svc->srv_ctl_waitq); 

	/* XXX maintain a list of all managed devices: insert here */

	/* And now, loop forever on requests */
	while (1) {

                wait_event(svc->srv_waitq, ptlrpc_check_event(svc));
                
                if (svc->srv_flags & SVC_SIGNAL) {
                        EXIT;
                        break;
                }

                if (svc->srv_flags & SVC_STOPPING) {
                        EXIT;
                        break;
                }

                if (svc->srv_flags & SVC_EVENT) { 
			struct ptlrpc_request request;
                        svc->srv_flags = SVC_RUNNING; 

                        /* FIXME: If we move to an event-driven model,
                         * we should put the request on the stack of
                         * mds_handle instead. */
                        memset(&request, 0, sizeof(request));
                        request.rq_reqbuf = svc->srv_ev.mem_desc.start + svc->srv_ev.offset;
                        request.rq_reqlen = svc->srv_ev.mem_desc.length;
                        request.rq_xid = svc->srv_ev.match_bits;
                        CERROR("got req %d\n", request.rq_xid);

                        request.rq_peer.peer_nid = svc->srv_ev.initiator.nid;
                        /* FIXME: this NI should be the incoming NI.
                         * We don't know how to find that from here. */
                        request.rq_peer.peer_ni = svc->srv_self.peer_ni;
                        rc = svc->srv_handler(obddev, svc, &request);
                        ptl_received_rpc(svc);
                        continue;
                }

                if (svc->srv_flags & SVC_LIST) { 
			struct ptlrpc_request *request;
                        svc->srv_flags = SVC_RUNNING; 

                        spin_lock(&svc->srv_lock);
                        request = list_entry(svc->srv_reqs.next,
                                             struct ptlrpc_request,
                                             rq_list);
                        list_del(&request->rq_list);
                        spin_unlock(&svc->srv_lock);
                        rc = svc->srv_handler(obddev, svc, request);
                        continue;
                }
                CERROR("unknown break in service"); 
                break; 
        }

	svc->srv_thread = NULL;
        svc->srv_flags = SVC_STOPPED;
	wake_up(&svc->srv_ctl_waitq);
	CERROR("svc exiting process %d\n", current->pid);
	return 0;
}

void ptlrpc_stop_thread(struct ptlrpc_service *svc)
{
	svc->srv_flags = SVC_STOPPING;

        wake_up(&svc->srv_waitq);
        wait_event_interruptible(svc->srv_ctl_waitq,  (svc->srv_flags & SVC_STOPPED));
}

int ptlrpc_start_thread(struct obd_device *dev, struct ptlrpc_service *svc,
                                char *name)
{
        struct ptlrpc_svc_data d;
        int rc;
	ENTRY;

        d.dev = dev;
        d.svc = svc;
        d.name = name;

	init_waitqueue_head(&svc->srv_waitq);

	init_waitqueue_head(&svc->srv_ctl_waitq);
	rc = kernel_thread(ptlrpc_main, (void *) &d, 
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) { 
                CERROR("cannot start thread\n"); 
                return -EINVAL;
        }
        wait_event(svc->srv_ctl_waitq, svc->srv_flags & SVC_RUNNING);

	EXIT;
        return 0;
}


int rpc_register_service(struct ptlrpc_service *service, char *uuid)
{
        struct lustre_peer peer;
        int rc, i;

        rc = kportal_uuid_to_peer(uuid, &peer);
        if (rc != 0) {
                CERROR("Invalid uuid \"%s\"\n", uuid);
                return -EINVAL;
        }

        service->srv_ring_length = RPC_RING_LENGTH;
        service->srv_me_active = 0;
        service->srv_md_active = 0;

        service->srv_id.addr_kind = PTL_ADDR_GID;
        service->srv_id.gid = PTL_ID_ANY;
        service->srv_id.rid = PTL_ID_ANY;

        rc = PtlEQAlloc(peer.peer_ni, 128, server_request_callback,
                        service, &(service->srv_eq_h));

        if (rc != PTL_OK) {
                CERROR("PtlEQAlloc failed: %d\n", rc);
                return rc;
        }

        /* Attach the leading ME on which we build the ring */
        rc = PtlMEAttach(peer.peer_ni, service->srv_req_portal,
                         service->srv_id, 0, ~0, PTL_RETAIN,
                         &(service->srv_me_h[0]));

        if (rc != PTL_OK) {
                CERROR("PtlMEAttach failed: %d\n", rc);
                return rc;
        }

        for (i = 0; i < service->srv_ring_length; i++) {
                OBD_ALLOC(service->srv_buf[i], service->srv_buf_size);

                if (service->srv_buf[i] == NULL) {
                        CERROR("no memory\n");
                        return -ENOMEM;
                }

                /* Insert additional ME's to the ring */
                if (i > 0) {
                        rc = PtlMEInsert(service->srv_me_h[i-1],
                                         service->srv_id, 0, ~0, PTL_RETAIN,
                                         PTL_INS_AFTER,&(service->srv_me_h[i]));
                        service->srv_me_tail = i;

                        if (rc != PTL_OK) {
                                CERROR("PtlMEInsert failed: %d\n", rc);
                                return rc;
                        }
                }

                service->srv_ref_count[i] = 0;
                service->srv_md[i].start        = service->srv_buf[i];
                service->srv_md[i].length        = service->srv_buf_size;
                service->srv_md[i].threshold        = PTL_MD_THRESH_INF;
                service->srv_md[i].options        = PTL_MD_OP_PUT;
                service->srv_md[i].user_ptr        = service;
                service->srv_md[i].eventq        = service->srv_eq_h;

                rc = PtlMDAttach(service->srv_me_h[i], service->srv_md[i],
                                 PTL_RETAIN, &(service->srv_md_h[i]));

                if (rc != PTL_OK) {
                        /* cleanup */
                        CERROR("PtlMDAttach failed: %d\n", rc);
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
                        CERROR("PtlMDUnlink failed: %d\n", rc);
        
                rc = PtlMEUnlink(service->srv_me_h[i]);
                if (rc)
                        CERROR("PtlMEUnlink failed: %d\n", rc);
        
                OBD_FREE(service->srv_buf[i], service->srv_buf_size);                
        }

        rc = PtlEQFree(service->srv_eq_h);
        if (rc)
                CERROR("PtlEQFree failed: %d\n", rc);

        return 0;
}

