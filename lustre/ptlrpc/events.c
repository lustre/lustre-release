/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#ifdef __KERNEL__
#include <linux/module.h>
#else
#include <liblustre.h>
#endif
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include "ptlrpc_internal.h"

#if !defined(__KERNEL__) && CRAY_PORTALS
/* forward ref in events.c */
static void cray_portals_callback(ptl_event_t *ev);
#endif

ptl_handle_ni_t   ptlrpc_ni_h;
ptl_handle_eq_t   ptlrpc_eq_h;

/*  
 *  Client's outgoing request callback
 */
void request_out_callback(ptl_event_t *ev)
{
        struct ptlrpc_cb_id   *cbid = ev->md.user_ptr;
        struct ptlrpc_request *req = cbid->cbid_arg;
        unsigned long          flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_SEND_END ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT (ev->unlinked);

        DEBUG_REQ((ev->ni_fail_type == PTL_NI_OK) ? D_NET : D_ERROR, req,
                  "type %d, status %d", ev->type, ev->ni_fail_type);

        if (ev->type == PTL_EVENT_UNLINK ||
            ev->ni_fail_type != PTL_NI_OK) {

                /* Failed send: make it seem like the reply timed out, just
                 * like failing sends in client.c does currently...  */

                spin_lock_irqsave(&req->rq_lock, flags);
                req->rq_net_err = 1;
                spin_unlock_irqrestore(&req->rq_lock, flags);
                
                ptlrpc_wake_client_req(req);
        }

        /* this balances the atomic_inc in ptl_send_rpc() */
        ptlrpc_req_finished(req);
        EXIT;
}

/*
 * Client's incoming reply callback
 */
void reply_in_callback(ptl_event_t *ev)
{
        struct ptlrpc_cb_id   *cbid = ev->md.user_ptr;
        struct ptlrpc_request *req = cbid->cbid_arg;
        unsigned long flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_PUT_END ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT (ev->unlinked);
        LASSERT (ev->md.start == req->rq_repmsg);
        LASSERT (ev->offset == 0);
        LASSERT (ev->mlength <= req->rq_replen);
        
        DEBUG_REQ((ev->ni_fail_type == PTL_NI_OK) ? D_NET : D_ERROR, req,
                  "type %d, status %d", ev->type, ev->ni_fail_type);

        spin_lock_irqsave (&req->rq_lock, flags);

        LASSERT (req->rq_receiving_reply);
        req->rq_receiving_reply = 0;

        if (ev->type == PTL_EVENT_PUT_END &&
            ev->ni_fail_type == PTL_NI_OK) {
                req->rq_replied = 1;
                req->rq_nob_received = ev->mlength;
        }

        /* NB don't unlock till after wakeup; req can disappear under us
         * since we don't have our own ref */
        ptlrpc_wake_client_req(req);

        spin_unlock_irqrestore (&req->rq_lock, flags);
        EXIT;
}

/* 
 * Client's bulk has been written/read
 */
void client_bulk_callback (ptl_event_t *ev)
{
        struct ptlrpc_cb_id     *cbid = ev->md.user_ptr;
        struct ptlrpc_bulk_desc *desc = cbid->cbid_arg;
        unsigned long            flags;
        ENTRY;

        LASSERT ((desc->bd_type == BULK_PUT_SINK && 
                  ev->type == PTL_EVENT_PUT_END) ||
                 (desc->bd_type == BULK_GET_SOURCE &&
                  ev->type == PTL_EVENT_GET_END) ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT (ev->unlinked);

        CDEBUG((ev->ni_fail_type == PTL_NI_OK) ? D_NET : D_ERROR,
               "event type %d, status %d, desc %p\n", 
               ev->type, ev->ni_fail_type, desc);

        spin_lock_irqsave (&desc->bd_lock, flags);

        LASSERT(desc->bd_network_rw);
        desc->bd_network_rw = 0;

        if (ev->type != PTL_EVENT_UNLINK &&
            ev->ni_fail_type == PTL_NI_OK) {
                desc->bd_success = 1;
                desc->bd_nob_transferred = ev->mlength;
        }

        /* NB don't unlock till after wakeup; desc can disappear under us
         * otherwise */
        ptlrpc_wake_client_req(desc->bd_req);

        spin_unlock_irqrestore (&desc->bd_lock, flags);
        EXIT;
}

/* 
 * Server's incoming request callback
 */
void request_in_callback(ptl_event_t *ev)
{
        struct ptlrpc_cb_id               *cbid = ev->md.user_ptr;
        struct ptlrpc_request_buffer_desc *rqbd = cbid->cbid_arg;
        struct ptlrpc_service             *service = rqbd->rqbd_service;
        struct ptlrpc_request             *req;
        unsigned long                     flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_PUT_END ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT ((char *)ev->md.start >= rqbd->rqbd_buffer);
        LASSERT ((char *)ev->md.start + ev->offset + ev->mlength <=
                 rqbd->rqbd_buffer + service->srv_buf_size);

        CDEBUG((ev->ni_fail_type == PTL_OK) ? D_NET : D_ERROR,
               "event type %d, status %d, service %s\n", 
               ev->type, ev->ni_fail_type, service->srv_name);

        if (ev->unlinked) {
                /* If this is the last request message to fit in the
                 * request buffer we can use the request object embedded in
                 * rqbd.  Note that if we failed to allocate a request,
                 * we'd have to re-post the rqbd, which we can't do in this
                 * context. */
                req = &rqbd->rqbd_req;
                memset(req, 0, sizeof (*req));
        } else {
                LASSERT (ev->type == PTL_EVENT_PUT_END);
                if (ev->ni_fail_type != PTL_NI_OK) {
                        /* We moaned above already... */
                        return;
                }
                OBD_ALLOC_GFP(req, sizeof(*req), GFP_ATOMIC);
                if (req == NULL) {
                        CERROR("Can't allocate incoming request descriptor: "
                               "Dropping %s RPC from %s\n",
                               service->srv_name, 
                               libcfs_id2str(ev->initiator));
                        return;
                }
        }

        /* NB we ABSOLUTELY RELY on req being zeroed, so pointers are NULL,
         * flags are reset and scalars are zero.  We only set the message
         * size to non-zero if this was a successful receive. */
        req->rq_xid = ev->match_bits;
        req->rq_reqmsg = ev->md.start + ev->offset;
        if (ev->type == PTL_EVENT_PUT_END &&
            ev->ni_fail_type == PTL_NI_OK)
                req->rq_reqlen = ev->mlength;
        do_gettimeofday(&req->rq_arrival_time);
        req->rq_peer = ev->initiator;
        req->rq_rqbd = rqbd;
        req->rq_phase = RQ_PHASE_NEW;
#if CRAY_PORTALS
        req->rq_uid = ev->uid;
#endif
        
        spin_lock_irqsave (&service->srv_lock, flags);

        req->rq_history_seq = service->srv_request_seq++;
        list_add_tail(&req->rq_history_list, &service->srv_request_history);

        if (ev->unlinked) {
                service->srv_nrqbd_receiving--;
                if (ev->type != PTL_EVENT_UNLINK &&
                    service->srv_nrqbd_receiving == 0) {
                        /* This service is off-air because all its request
                         * buffers are busy.  Portals will start dropping
                         * incoming requests until more buffers get posted.  
                         * NB don't moan if it's because we're tearing down the
                         * service. */
                        CWARN("All %s request buffers busy\n",
                              service->srv_name);
                }
                /* req takes over the network's ref on rqbd */
        } else {
                /* req takes a ref on rqbd */
                rqbd->rqbd_refcount++;
        }

        list_add_tail(&req->rq_list, &service->srv_request_queue);
        service->srv_n_queued_reqs++;

        /* NB everything can disappear under us once the request
         * has been queued and we unlock, so do the wake now... */
        wake_up(&service->srv_waitq);

        spin_unlock_irqrestore(&service->srv_lock, flags);
        EXIT;
}

/*  
 *  Server's outgoing reply callback
 */
void reply_out_callback(ptl_event_t *ev)
{
        struct ptlrpc_cb_id       *cbid = ev->md.user_ptr;
        struct ptlrpc_reply_state *rs = cbid->cbid_arg;
        struct ptlrpc_service     *svc = rs->rs_service;
        unsigned long              flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_SEND_END ||
                 ev->type == PTL_EVENT_ACK ||
                 ev->type == PTL_EVENT_UNLINK);

        if (!rs->rs_difficult) {
                /* 'Easy' replies have no further processing so I drop the
                 * net's ref on 'rs' */
                LASSERT (ev->unlinked);
                ptlrpc_rs_decref(rs);
                atomic_dec (&svc->srv_outstanding_replies);
                EXIT;
                return;
        }

        LASSERT (rs->rs_on_net);

        if (ev->unlinked) {
                /* Last network callback.  The net's ref on 'rs' stays put
                 * until ptlrpc_server_handle_reply() is done with it */
                spin_lock_irqsave (&svc->srv_lock, flags);
                rs->rs_on_net = 0;
                ptlrpc_schedule_difficult_reply (rs);
                spin_unlock_irqrestore (&svc->srv_lock, flags);
        }

        EXIT;
}

/*
 * Server's bulk completion callback
 */
void server_bulk_callback (ptl_event_t *ev)
{
        struct ptlrpc_cb_id     *cbid = ev->md.user_ptr;
        struct ptlrpc_bulk_desc *desc = cbid->cbid_arg;
        unsigned long            flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_SEND_END ||
                 ev->type == PTL_EVENT_UNLINK ||
                 (desc->bd_type == BULK_PUT_SOURCE &&
                  ev->type == PTL_EVENT_ACK) ||
                 (desc->bd_type == BULK_GET_SINK &&
                  ev->type == PTL_EVENT_REPLY_END));

        CDEBUG((ev->ni_fail_type == PTL_NI_OK) ? D_NET : D_ERROR,
               "event type %d, status %d, desc %p\n", 
               ev->type, ev->ni_fail_type, desc);

        spin_lock_irqsave (&desc->bd_lock, flags);
        
        if ((ev->type == PTL_EVENT_ACK ||
             ev->type == PTL_EVENT_REPLY_END) &&
            ev->ni_fail_type == PTL_NI_OK) {
                /* We heard back from the peer, so even if we get this
                 * before the SENT event (oh yes we can), we know we
                 * read/wrote the peer buffer and how much... */
                desc->bd_success = 1;
                desc->bd_nob_transferred = ev->mlength;
        }

        if (ev->unlinked) {
                /* This is the last callback no matter what... */
                desc->bd_network_rw = 0;
                wake_up(&desc->bd_waitq);
        }

        spin_unlock_irqrestore (&desc->bd_lock, flags);
        EXIT;
}

static void ptlrpc_master_callback(ptl_event_t *ev)
{
        struct ptlrpc_cb_id *cbid = ev->md.user_ptr;
        void (*callback)(ptl_event_t *ev) = cbid->cbid_fn;

        /* Honestly, it's best to find out early. */
        LASSERT (cbid->cbid_arg != LP_POISON);
        LASSERT (callback == request_out_callback ||
                 callback == reply_in_callback ||
                 callback == client_bulk_callback ||
                 callback == request_in_callback ||
                 callback == reply_out_callback ||
                 callback == server_bulk_callback);
        
        callback (ev);
}

int ptlrpc_uuid_to_peer (struct obd_uuid *uuid, ptl_process_id_t *peer)
{
        peer->pid = LUSTRE_SRV_PTL_PID;
        return lustre_uuid_to_peer (uuid->uuid, &peer->nid);
}

void ptlrpc_ni_fini(void)
{
        wait_queue_head_t   waitq;
        struct l_wait_info  lwi;
        int                 rc;
        int                 retries;
        
        /* Wait for the event queue to become idle since there may still be
         * messages in flight with pending events (i.e. the fire-and-forget
         * messages == client requests and "non-difficult" server
         * replies */

        for (retries = 0;; retries++) {
                rc = PtlEQFree(ptlrpc_eq_h);
                switch (rc) {
                default:
                        LBUG();

                case PTL_OK:
                        PtlNIFini(ptlrpc_ni_h);
                        return;
                        
                case PTL_EQ_IN_USE:
                        if (retries != 0)
                                CWARN("Event queue still busy\n");
                        
                        /* Wait for a bit */
                        init_waitqueue_head(&waitq);
                        lwi = LWI_TIMEOUT(2*HZ, NULL, NULL);
                        l_wait_event(waitq, 0, &lwi);
                        break;
                }
        }
        /* notreached */
}

ptl_pid_t ptl_get_pid(void)
{
        ptl_pid_t        pid;

#ifndef  __KERNEL__
        pid = getpid();
# if CRAY_PORTALS
	/* hack to keep pid in range accepted by ernal */
	pid &= 0xFF;
	if (pid == LUSTRE_SRV_PTL_PID)
		pid++;
# endif
#else
        pid = LUSTRE_SRV_PTL_PID;
#endif
        return pid;
}
        
int ptlrpc_ni_init(void)
{
        int              rc;
        char             str[20];
        ptl_pid_t        pid;

        pid = ptl_get_pid();

        /* We're not passing any limits yet... */
        rc = PtlNIInit(PTL_IFACE_DEFAULT, pid, NULL, NULL, &ptlrpc_ni_h);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                CDEBUG (D_NET, "Can't init network interface: %d\n", rc);
                return (-ENOENT);
        }

        CDEBUG(D_NET, "My pid is: %x\n", ptl_get_pid());
        
        PtlSnprintHandle(str, sizeof(str), ptlrpc_ni_h);
        CDEBUG (D_NET, "ptlrpc_ni_h: %s\n", str);

        /* CAVEAT EMPTOR: how we process portals events is _radically_
         * different depending on... */
#ifdef __KERNEL__
        /* kernel portals calls our master callback when events are added to
         * the event queue.  In fact lustre never pulls events off this queue,
         * so it's only sized for some debug history. */
# if CRAY_PORTALS
        rc = PtlNIDebug(pni->pni_ni_h, 0xffffffff);
        if (rc != PTL_OK)
                CDEBUG(D_ERROR, "Can't enable Cray Portals Debug: rc %d\n", rc);
# endif
        rc = PtlEQAlloc(ptlrpc_ni_h, 1024, ptlrpc_master_callback,
                        &ptlrpc_eq_h);
#else
        /* liblustre calls the master callback when it removes events from the
         * event queue.  The event queue has to be big enough not to drop
         * anything */
# if CRAY_PORTALS
        /* cray portals implements a non-standard callback to notify us there
         * are buffered events even when the app is not doing a filesystem
         * call. */
        rc = PtlEQAlloc(ptlrpc_ni_h, 10240, cray_portals_callback,
                        &ptlrpc_eq_h);
# else
        rc = PtlEQAlloc(ptlrpc_ni_h, 10240, PTL_EQ_HANDLER_NONE,
                        &ptlrpc_eq_h);
# endif
#endif
        if (rc == PTL_OK)
                return 0;
        
        CERROR ("Failed to allocate event queue: %d\n", rc);
        PtlNIFini(ptlrpc_ni_h);

        return (-ENOMEM);
}

#ifndef __KERNEL__
LIST_HEAD(liblustre_wait_callbacks);
void *liblustre_services_callback;

void *
liblustre_register_wait_callback (int (*fn)(void *arg), void *arg)
{
        struct liblustre_wait_callback *llwc;
        
        OBD_ALLOC(llwc, sizeof(*llwc));
        LASSERT (llwc != NULL);
        
        llwc->llwc_fn = fn;
        llwc->llwc_arg = arg;
        list_add_tail(&llwc->llwc_list, &liblustre_wait_callbacks);
        
        return (llwc);
}

void
liblustre_deregister_wait_callback (void *opaque)
{
        struct liblustre_wait_callback *llwc = opaque;
        
        list_del(&llwc->llwc_list);
        OBD_FREE(llwc, sizeof(*llwc));
}

int
liblustre_check_events (int timeout)
{
        ptl_event_t ev;
        int         rc;
        int         i;
        ENTRY;

        rc = PtlEQPoll(&ptlrpc_eq_h, 1, timeout * 1000, &ev, &i);
        if (rc == PTL_EQ_EMPTY)
                RETURN(0);
        
        LASSERT (rc == PTL_EQ_DROPPED || rc == PTL_OK);
        
        /* liblustre: no asynch callback so we can't affort to miss any
         * events... */
        if (rc == PTL_EQ_DROPPED) {
                CERROR ("Dropped an event!!!\n");
                abort();
        }
        
        ptlrpc_master_callback (&ev);
        RETURN(1);
}

int liblustre_waiting = 0;

int
liblustre_wait_event (int timeout)
{
        struct list_head               *tmp;
        struct liblustre_wait_callback *llwc;
        int                             found_something = 0;

        /* single threaded recursion check... */
        liblustre_waiting = 1;

        for (;;) {
                /* Deal with all pending events */
                while (liblustre_check_events(0))
                        found_something = 1;

                /* Give all registered callbacks a bite at the cherry */
                list_for_each(tmp, &liblustre_wait_callbacks) {
                        llwc = list_entry(tmp, struct liblustre_wait_callback, 
                                          llwc_list);
                
                        if (llwc->llwc_fn(llwc->llwc_arg))
                                found_something = 1;
                }

                if (found_something || timeout == 0)
                        break;

                /* Nothing so far, but I'm allowed to block... */
                found_something = liblustre_check_events(timeout);
                if (!found_something)           /* still nothing */
                        break;                  /* I timed out */
        }

        liblustre_waiting = 0;

        return found_something;
}

#if CRAY_PORTALS
static void cray_portals_callback(ptl_event_t *ev)
{
        /* We get a callback from the client Cray portals implementation
         * whenever anyone calls PtlEQPoll(), and an event queue with a
         * callback handler has outstanding events.
         *
         * If it's not liblustre calling PtlEQPoll(), this lets us know we
         * have outstanding events which we handle with
         * liblustre_wait_event().
         *
         * Otherwise, we're already eagerly consuming events and we'd
         * handle events out of order if we recursed. */
        if (!liblustre_waiting)
                liblustre_wait_event(0);
}
#endif
#endif /* __KERNEL__ */

int ptlrpc_init_portals(void)
{
        int   rc = ptlrpc_ni_init();

        if (rc != 0) {
                CERROR("network initialisation failed\n");
                return -EIO;
        }
#ifndef __KERNEL__
        liblustre_services_callback = 
                liblustre_register_wait_callback(&liblustre_check_services, NULL);
#endif
        return 0;
}

void ptlrpc_exit_portals(void)
{
#ifndef __KERNEL__
        liblustre_deregister_wait_callback(liblustre_services_callback);
#endif
        ptlrpc_ni_fini();
}
