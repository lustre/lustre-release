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
extern int ptl_handled_rpc(struct ptlrpc_service *service, void *start);

static int ptlrpc_check_event(struct ptlrpc_service *svc)
{
        int rc = 0;

        spin_lock(&svc->srv_lock);
        if (sigismember(&(current->pending.signal), SIGKILL) ||
            sigismember(&(current->pending.signal), SIGTERM) ||
            sigismember(&(current->pending.signal), SIGINT)) {
                svc->srv_flags |= SVC_KILLED;
                GOTO(out, rc = 1);
        }

        if (svc->srv_flags & SVC_STOPPING)
                GOTO(out, rc = 1);

        if (svc->srv_flags & SVC_EVENT)
                LBUG();

        if (ptl_is_valid_handle(&svc->srv_eq_h)) {
                int err;
                err = PtlEQGet(svc->srv_eq_h, &svc->srv_ev);

                if (err == PTL_OK) {
                        svc->srv_flags |= SVC_EVENT;
                        GOTO(out, rc = 1);
                }

                if (err != PTL_EQ_EMPTY) {
                        CDEBUG(D_NET, "BUG: PtlEQGet returned %d\n", rc);
                        LBUG();
                }

                GOTO(out, rc = 0);
        }

        if (!list_empty(&svc->srv_reqs)) {
                svc->srv_flags |= SVC_LIST;
                GOTO(out, rc = 1);
        }

        EXIT;
 out:
        spin_unlock(&svc->srv_lock);
        return rc;
}

struct ptlrpc_service *
ptlrpc_init_svc(__u32 bufsize, int req_portal, int rep_portal, char *uuid,
                svc_handler_t handler)
{
        int err;
        int rc, i;
        struct ptlrpc_service *service;

        OBD_ALLOC(service, sizeof(*service));
        if (!service) {
                LBUG();
                RETURN(NULL);
        }

        spin_lock_init(&service->srv_lock);
        INIT_LIST_HEAD(&service->srv_reqs);
        init_waitqueue_head(&service->srv_ctl_waitq);
        init_waitqueue_head(&service->srv_waitq);

        service->srv_thread = NULL;
        service->srv_flags = 0;

        service->srv_buf_size = bufsize;
        service->srv_rep_portal = rep_portal;
        service->srv_req_portal = req_portal;
        service->srv_handler = handler;

        err = kportal_uuid_to_peer(uuid, &service->srv_self);
        if (err) {
                CERROR("cannot get peer for uuid %s", uuid);
                GOTO(err_free, NULL);
        }

        service->srv_ring_length = RPC_RING_LENGTH;
        service->srv_id.nid = PTL_ID_ANY;
        service->srv_id.pid = PTL_ID_ANY;

        rc = PtlEQAlloc(service->srv_self.peer_ni, 128,
                        server_request_callback,
                        service, &(service->srv_eq_h));

        if (rc != PTL_OK) {
                CERROR("PtlEQAlloc failed: %d\n", rc);
                LBUG();
                GOTO(err_free, NULL);
        }

        for (i = 0; i < service->srv_ring_length; i++) {
                OBD_ALLOC(service->srv_buf[i], service->srv_buf_size);
                if (service->srv_buf[i] == NULL) {
                        CERROR("no memory\n");
                        LBUG();
                        GOTO(err_ring, NULL);
                }
                service->srv_ref_count[i] = 0;
                ptlrpc_link_svc_me(service, i);
        }

        CDEBUG(D_NET, "Starting service listening on portal %d\n",
               service->srv_req_portal);

        return service;
err_ring:
        service->srv_ring_length = i;
        rpc_unregister_service(service); // XXX verify this is right
        PtlEQFree(service->srv_eq_h);
err_free:
        OBD_FREE(service, sizeof(*service));
        return NULL;
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

                spin_lock(&svc->srv_lock);
                if (svc->srv_flags & SVC_SIGNAL) {
                        spin_unlock(&svc->srv_lock);
                        EXIT;
                        break;
                }

                if (svc->srv_flags & SVC_STOPPING) {
                        spin_unlock(&svc->srv_lock);
                        EXIT;
                        break;
                }

                if (svc->srv_flags & SVC_EVENT) {
                        struct ptlrpc_request request;
                        void *start;
                        svc->srv_flags = SVC_RUNNING;

                        /* FIXME: If we move to an event-driven model,
                         * we should put the request on the stack of
                         * mds_handle instead. */
                        start = svc->srv_ev.mem_desc.start;
                        memset(&request, 0, sizeof(request));
                        request.rq_obd = obddev;
                        request.rq_reqbuf = (svc->srv_ev.mem_desc.start +
                                             svc->srv_ev.offset);
                        request.rq_reqlen = svc->srv_ev.mem_desc.length;
                        request.rq_xid = svc->srv_ev.match_bits;
                        CDEBUG(D_NET, "got req %d\n", request.rq_xid);

                        request.rq_peer.peer_nid = svc->srv_ev.initiator.nid;
                        /* FIXME: this NI should be the incoming NI.
                         * We don't know how to find that from here. */
                        request.rq_peer.peer_ni = svc->srv_self.peer_ni;
                        svc->srv_flags &= ~SVC_EVENT;

                        spin_unlock(&svc->srv_lock);
                        rc = svc->srv_handler(obddev, svc, &request);
                        ptl_handled_rpc(svc, start);
                        continue;
                }

                if (svc->srv_flags & SVC_LIST) {
                        struct ptlrpc_request *request;
                        svc->srv_flags = SVC_RUNNING;

                        request = list_entry(svc->srv_reqs.next,
                                             struct ptlrpc_request,
                                             rq_list);
                        list_del(&request->rq_list);
                        spin_unlock(&svc->srv_lock);
                        rc = svc->srv_handler(obddev, svc, request);
                        continue;
                }
                CERROR("unknown break in service");
                spin_unlock(&svc->srv_lock);
                EXIT;
                break;
        }

        svc->srv_thread = NULL;
        svc->srv_flags = SVC_STOPPED;
        wake_up(&svc->srv_ctl_waitq);
        CDEBUG(D_NET, "svc exiting process %d\n", current->pid);
        return 0;
}

void ptlrpc_stop_thread(struct ptlrpc_service *svc)
{
        svc->srv_flags = SVC_STOPPING;

        wake_up(&svc->srv_waitq);
        wait_event_interruptible(svc->srv_ctl_waitq,
                                 (svc->srv_flags & SVC_STOPPED));
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
                RETURN(-EINVAL);
        }
        wait_event(svc->srv_ctl_waitq, svc->srv_flags & SVC_RUNNING);

        RETURN(0);
}

int rpc_unregister_service(struct ptlrpc_service *service)
{
        int rc, i;

        for (i = 0; i < service->srv_ring_length; i++) {
                if (ptl_is_valid_handle(&(service->srv_me_h[i]))) {
                        rc = PtlMEUnlink(service->srv_me_h[i]);
                        if (rc)
                                CERROR("PtlMEUnlink failed: %d\n", rc);
                        ptl_set_inv_handle(&(service->srv_me_h[i]));
                }

                if (service->srv_buf[i] != NULL)
                        OBD_FREE(service->srv_buf[i], service->srv_buf_size);
                service->srv_buf[i] = NULL;
        }

        rc = PtlEQFree(service->srv_eq_h);
        if (rc)
                CERROR("PtlEQFree failed: %d\n", rc);

        return 0;
}
