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
#ifndef __KERNEL__
#include <liblustre.h>
#include <linux/kp30.h>
#endif
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <portals/types.h>
#include "ptlrpc_internal.h"

extern int request_in_callback(ptl_event_t *ev);

static int ptlrpc_check_event(struct ptlrpc_service *svc,
                              struct ptlrpc_thread *thread, ptl_event_t *event)
{
        struct ptlrpc_srv_ni *srv_ni;
        int i;
        int idx;
        int rc;
        ENTRY;

        spin_lock(&svc->srv_lock);

        if (thread->t_flags & SVC_STOPPING)
                GOTO(out, rc = 1);

        LASSERT ((thread->t_flags & SVC_EVENT) == 0);
        LASSERT (ptlrpc_ninterfaces > 0);

        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                idx = (svc->srv_interface_rover + i) % ptlrpc_ninterfaces;
                srv_ni = &svc->srv_interfaces[idx];

                LASSERT (!PtlHandleEqual (srv_ni->sni_eq_h, PTL_HANDLE_NONE));

                rc = PtlEQGet(srv_ni->sni_eq_h, event);
                switch (rc) {
                case PTL_OK:
                        /* next time start with the next interface */
                        svc->srv_interface_rover = (idx+1) % ptlrpc_ninterfaces;
                        thread->t_flags |= SVC_EVENT;
                        GOTO(out, rc = 1);

                case PTL_EQ_EMPTY:
                        continue;

                default:
                        CERROR("BUG: PtlEQGet returned %d\n", rc);
                        LBUG();
                }
        }
        rc = 0;
        EXIT;
 out:
        spin_unlock(&svc->srv_lock);
        return rc;
}

struct ptlrpc_service * ptlrpc_init_svc(__u32 nevents, __u32 nbufs,
                                        __u32 bufsize, __u32 max_req_size,
                                        int req_portal, int rep_portal,
                                        svc_handler_t handler, char *name,
                                        struct obd_device *obddev)
{
        int i, j, ssize, rc;
        struct ptlrpc_service *service;
        struct ptlrpc_srv_ni  *srv_ni;
        ENTRY;

        LASSERT (ptlrpc_ninterfaces > 0);

        ssize = offsetof (struct ptlrpc_service,
                          srv_interfaces[ptlrpc_ninterfaces]);
        OBD_ALLOC(service, ssize);
        if (service == NULL)
                RETURN(NULL);

        service->srv_name = name;
        spin_lock_init(&service->srv_lock);
        INIT_LIST_HEAD(&service->srv_threads);
        init_waitqueue_head(&service->srv_waitq);

        service->srv_max_req_size = max_req_size;
        service->srv_buf_size = bufsize;

        service->srv_rep_portal = rep_portal;
        service->srv_req_portal = req_portal;
        service->srv_handler = handler;
        service->srv_interface_rover = 0;

        /* First initialise enough for early teardown */
        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                srv_ni = &service->srv_interfaces[i];

                srv_ni->sni_service = service;
                srv_ni->sni_ni = &ptlrpc_interfaces[i];
                srv_ni->sni_eq_h = PTL_HANDLE_NONE;
                INIT_LIST_HEAD(&srv_ni->sni_rqbds);
                srv_ni->sni_nrqbds = 0;
                atomic_set(&srv_ni->sni_nrqbds_receiving, 0);
        }

        /* Now allocate the event queue and request buffers, assuming all
         * interfaces require the same level of buffering. */
        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                srv_ni = &service->srv_interfaces[i];
                CDEBUG (D_NET, "%s: initialising interface %s\n", name,
                        srv_ni->sni_ni->pni_name);

                rc = PtlEQAlloc(srv_ni->sni_ni->pni_ni_h, nevents,
                                request_in_callback, &(srv_ni->sni_eq_h));
                if (rc != PTL_OK) {
                        CERROR("%s.%d: PtlEQAlloc on %s failed: %d\n",
                               name, i, srv_ni->sni_ni->pni_name, rc);
                        GOTO (failed, NULL);
                }

                for (j = 0; j < nbufs; j++) {
                        struct ptlrpc_request_buffer_desc *rqbd;

                        OBD_ALLOC(rqbd, sizeof(*rqbd));
                        if (rqbd == NULL) {
                                CERROR ("%s.%d: Can't allocate request "
                                        "descriptor %d on %s\n",
                                        name, i, srv_ni->sni_nrqbds,
                                        srv_ni->sni_ni->pni_name);
                                GOTO(failed, NULL);
                        }

                        rqbd->rqbd_srv_ni = srv_ni;
                        rqbd->rqbd_me_h = PTL_HANDLE_NONE;
                        atomic_set(&rqbd->rqbd_refcount, 0);

                        OBD_ALLOC(rqbd->rqbd_buffer, service->srv_buf_size);
                        if (rqbd->rqbd_buffer == NULL) {
                                CERROR ("%s.%d: Can't allocate request "
                                        "buffer %d on %s\n",
                                        name, i, srv_ni->sni_nrqbds,
                                        srv_ni->sni_ni->pni_name);
                                OBD_FREE(rqbd, sizeof(*rqbd));
                                GOTO(failed, NULL);
                        }
                        list_add(&rqbd->rqbd_list, &srv_ni->sni_rqbds);
                        srv_ni->sni_nrqbds++;

                        ptlrpc_link_svc_me(rqbd);
                }
        }

        ptlrpc_lprocfs_register_service(obddev, service);

        CDEBUG(D_NET, "%s: Started on %d interfaces, listening on portal %d\n",
               service->srv_name, ptlrpc_ninterfaces, service->srv_req_portal);

        RETURN(service);
failed:
        ptlrpc_unregister_service(service);
        return NULL;
}

static int handle_incoming_request(struct obd_device *obddev,
                                   struct ptlrpc_service *svc,
                                   ptl_event_t *event,
                                   struct ptlrpc_request *request)
{
        struct ptlrpc_request_buffer_desc *rqbd = event->mem_desc.user_ptr;
        int rc;

        /* FIXME: If we move to an event-driven model, we should put the request
         * on the stack of mds_handle instead. */

        LASSERT (atomic_read (&rqbd->rqbd_refcount) > 0);
        LASSERT ((event->mem_desc.options & (PTL_MD_IOV | PTL_MD_KIOV)) == 0);
        LASSERT (rqbd->rqbd_srv_ni->sni_service == svc);
        LASSERT (rqbd->rqbd_buffer == event->mem_desc.start);
        LASSERT (event->offset + event->mlength <= svc->srv_buf_size);

        memset(request, 0, sizeof(*request));
        spin_lock_init (&request->rq_lock);
        INIT_LIST_HEAD(&request->rq_list);
        request->rq_svc = svc;
        request->rq_obd = obddev;
        request->rq_xid = event->match_bits;
        request->rq_reqmsg = event->mem_desc.start + event->offset;
        request->rq_reqlen = event->mlength;

#if SWAB_PARANOIA
        /* Clear request swab mask; this is a new request */
        request->rq_req_swab_mask = 0;
#endif
        rc = lustre_unpack_msg (request->rq_reqmsg, request->rq_reqlen);
        if (rc != 0) {
                CERROR ("error unpacking request: ptl %d from "LPX64
                        " xid "LPU64"\n", svc->srv_req_portal,
                       event->initiator.nid, request->rq_xid);
                goto out;
        }
        rc = -EINVAL;
        if (request->rq_reqmsg->type != PTL_RPC_MSG_REQUEST) {
                CERROR("wrong packet type received (type=%u)\n",
                       request->rq_reqmsg->type);
                goto out;
        }

        CDEBUG(D_NET, "got req "LPD64" (md: %p + %d)\n", request->rq_xid,
               event->mem_desc.start, event->offset);

        request->rq_peer.peer_nid = event->initiator.nid;
        request->rq_peer.peer_ni = rqbd->rqbd_srv_ni->sni_ni;

        request->rq_export = class_conn2export(&request->rq_reqmsg->handle);

        if (request->rq_export) {
                request->rq_connection = request->rq_export->exp_connection;
                ptlrpc_connection_addref(request->rq_connection);
                request->rq_export->exp_last_request_time =
                        LTIME_S(CURRENT_TIME);
        } else {
                /* create a (hopefully temporary) connection that will be used
                 * to send the reply if this call doesn't create an export.
                 * XXX revisit this when we revamp ptlrpc */
                request->rq_connection =
                        ptlrpc_get_connection(&request->rq_peer, NULL);
        }

        CDEBUG(D_RPCTRACE, "Handling RPC pname:cluuid:pid:xid:ni:nid:opc %s:%s:%d:"
               LPU64":%s:"LPX64":%d\n",
               current->comm,
               (request->rq_export ? 
                (char *)request->rq_export->exp_client_uuid.uuid : "0"), 
               request->rq_reqmsg->status, request->rq_xid,
               rqbd->rqbd_srv_ni->sni_ni->pni_name, event->initiator.nid,
               request->rq_reqmsg->opc);

        rc = svc->srv_handler(request);
        CDEBUG(D_RPCTRACE, "Handled RPC pname:cluuid:pid:xid:ni:nid:opc %s:%s:%d:"
               LPU64":%s:"LPX64":%d\n",
               current->comm,
               (request->rq_export ? 
                (char *)request->rq_export->exp_client_uuid.uuid : "0"),
               request->rq_reqmsg->status, request->rq_xid,
               rqbd->rqbd_srv_ni->sni_ni->pni_name, event->initiator.nid,
               request->rq_reqmsg->opc);

        ptlrpc_put_connection(request->rq_connection);
        if (request->rq_export != NULL)
                class_export_put(request->rq_export);

 out:
        if (atomic_dec_and_test (&rqbd->rqbd_refcount)) /* last reference? */
                ptlrpc_link_svc_me (rqbd);

        return rc;
}

/* Don't use daemonize, it removes fs struct from new thread (bug 418) */
void ptlrpc_daemonize(void)
{
        exit_mm(current);

        current->session = 1;
        current->pgrp = 1;
        current->tty = NULL;

        exit_files(current);
        reparent_to_init();
}

static int ptlrpc_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct obd_device *obddev = data->dev;
        struct ptlrpc_service *svc = data->svc;
        struct ptlrpc_thread *thread = data->thread;
        struct ptlrpc_request *request;
        ptl_event_t *event;
        int rc = 0;
        unsigned long flags;
        cycles_t workdone_time = -1;
        cycles_t svc_workcycles = -1;
        ENTRY;

        lock_kernel();
        ptlrpc_daemonize();

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
        sprintf(current->comm, "%s|%d", data->name,current->thread.extern_pid);
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        sprintf(current->comm, "%s|%d", data->name,
                current->thread.mode.tt.extern_pid);
#else
        strcpy(current->comm, data->name);
#endif
        unlock_kernel();

        OBD_ALLOC(event, sizeof(*event));
        if (!event)
                GOTO(out, rc = -ENOMEM);
        OBD_ALLOC(request, sizeof(*request));
        if (!request)
                GOTO(out_event, rc = -ENOMEM);

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        /* XXX maintain a list of all managed devices: insert here */

        /* And now, loop forever on requests */
        while (1) {
                struct l_wait_info lwi = { 0 };
                l_wait_event(svc->srv_waitq,
                             ptlrpc_check_event(svc, thread, event), &lwi);

                if (thread->t_flags & SVC_STOPPING) {
                        spin_lock(&svc->srv_lock);
                        thread->t_flags &= ~SVC_STOPPING;
                        spin_unlock(&svc->srv_lock);

                        EXIT;
                        break;
                }

                if (thread->t_flags & SVC_EVENT) {
                        cycles_t  workstart_time;

                        spin_lock(&svc->srv_lock);
                        thread->t_flags &= ~SVC_EVENT;
                        /* Update Service Statistics */
                        workstart_time = get_cycles();
                        if (workdone_time != -1 && svc->svc_stats != NULL) {
                                /* Stats for req(n) are updated just before
                                 * req(n+1) is executed. This avoids need to
                                 * reacquire svc->srv_lock after
                                 * call to handling_request().
                                 */
                                int opc;

                                /* req_waittime */
                                lprocfs_counter_add(svc->svc_stats,
                                                    PTLRPC_REQWAIT_CNTR,
                                                    (workstart_time -
                                                     event->arrival_time));
                                /* svc_eqdepth */
                                /* Wait for b_eq branch
                                lprocfs_counter_add(svc->svc_stats,
                                                    PTLRPC_SVCEQDEPTH_CNTR,
                                                    0);
                                */
                                /* svc_idletime */
                                lprocfs_counter_add(svc->svc_stats,
                                                    PTLRPC_SVCIDLETIME_CNTR,
                                                    (workstart_time -
                                                     workdone_time));
                                /* previous request */
                                opc = opcode_offset(request->rq_reqmsg->opc);
                                if (opc > 0) {
                                        LASSERT(opc < LUSTRE_MAX_OPCODES);
                                        lprocfs_counter_add(svc->svc_stats, opc,
                                                            PTLRPC_LAST_CNTR +
                                                            svc_workcycles);
                                }
                        }
                        spin_unlock(&svc->srv_lock);

                        rc = handle_incoming_request(obddev, svc, event,
                                                     request);
                        workdone_time = get_cycles();
                        svc_workcycles = workdone_time - workstart_time;
                        continue;
                }

                CERROR("unknown break in service");
                LBUG();
                EXIT;
                break;
        }

        /* NB should wait for all SENT callbacks to complete before exiting
         * here.  Unfortunately at this time there is no way to track this
         * state.
         */
        OBD_FREE(request, sizeof(*request));
out_event:
        OBD_FREE(event, sizeof(*event));
out:
        thread->t_flags = SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);

        CDEBUG(D_NET, "service thread exiting, process %d: rc = %d\n",
               current->pid, rc);
        return rc;
}

static void ptlrpc_stop_thread(struct ptlrpc_service *svc,
                               struct ptlrpc_thread *thread)
{
        struct l_wait_info lwi = { 0 };

        spin_lock(&svc->srv_lock);
        thread->t_flags = SVC_STOPPING;
        spin_unlock(&svc->srv_lock);

        wake_up(&svc->srv_waitq);
        l_wait_event(thread->t_ctl_waitq, (thread->t_flags & SVC_STOPPED),
                     &lwi);
}

void ptlrpc_stop_all_threads(struct ptlrpc_service *svc)
{
        spin_lock(&svc->srv_lock);
        while (!list_empty(&svc->srv_threads)) {
                struct ptlrpc_thread *thread;
                thread = list_entry(svc->srv_threads.next, struct ptlrpc_thread,
                                    t_link);
                spin_unlock(&svc->srv_lock);
                ptlrpc_stop_thread(svc, thread);
                spin_lock(&svc->srv_lock);
                list_del(&thread->t_link);
                OBD_FREE(thread, sizeof(*thread));
        }
        spin_unlock(&svc->srv_lock);
}

int ptlrpc_start_thread(struct obd_device *dev, struct ptlrpc_service *svc,
                        char *name)
{
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        struct ptlrpc_thread *thread;
        int rc;
        ENTRY;

        OBD_ALLOC(thread, sizeof(*thread));
        if (thread == NULL)
                RETURN(-ENOMEM);
        init_waitqueue_head(&thread->t_ctl_waitq);

        d.dev = dev;
        d.svc = svc;
        d.name = name;
        d.thread = thread;

        spin_lock(&svc->srv_lock);
        list_add(&thread->t_link, &svc->srv_threads);
        spin_unlock(&svc->srv_lock);

        /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in ptlrpc_daemonize() right away.
         */
        rc = kernel_thread(ptlrpc_main, &d, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                OBD_FREE(thread, sizeof(*thread));
                RETURN(rc);
        }
        l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_RUNNING, &lwi);

        RETURN(0);
}

int ptlrpc_unregister_service(struct ptlrpc_service *service)
{
        int i, rc;
        struct ptlrpc_srv_ni *srv_ni;

        LASSERT (list_empty (&service->srv_threads));

        /* XXX We could reply (with failure) to all buffered requests
         * _after_ unlinking _all_ the request buffers, but _before_
         * freeing them.
         */

        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                srv_ni = &service->srv_interfaces[i];
                CDEBUG (D_NET, "%s: tearing down interface %s\n",
                        service->srv_name, srv_ni->sni_ni->pni_name);

                while (!list_empty (&srv_ni->sni_rqbds)) {
                        struct ptlrpc_request_buffer_desc *rqbd =
                                list_entry (srv_ni->sni_rqbds.next,
                                            struct ptlrpc_request_buffer_desc,
                                            rqbd_list);

                        list_del (&rqbd->rqbd_list);

                        LASSERT (atomic_read (&rqbd->rqbd_refcount) > 0);
                        /* refcount could be anything; it's possible for
                         * the buffers to continued to get filled after all
                         * the server threads exited.  But we know they
                         * _have_ exited.
                         */

                        (void) PtlMEUnlink(rqbd->rqbd_me_h);
                        /* The callback handler could have unlinked this ME
                         * already (we're racing with her) but it's safe to
                         * ensure it _has_ been unlinked.
                         */

                        OBD_FREE (rqbd->rqbd_buffer, service->srv_buf_size);
                        OBD_FREE (rqbd, sizeof (*rqbd));
                        srv_ni->sni_nrqbds--;
                }

                LASSERT (srv_ni->sni_nrqbds == 0);

                if (!PtlHandleEqual (srv_ni->sni_eq_h, PTL_HANDLE_NONE)) {
                        rc = PtlEQFree(srv_ni->sni_eq_h);
                        if (rc)
                                CERROR("%s.%d: PtlEQFree failed on %s: %d\n",
                                       service->srv_name, i,
                                       srv_ni->sni_ni->pni_name, rc);
                }
        }

        ptlrpc_lprocfs_unregister_service(service);

        OBD_FREE(service,
                 offsetof (struct ptlrpc_service,
                           srv_interfaces[ptlrpc_ninterfaces]));
        return 0;
}
