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

struct ptlrpc_ni  ptlrpc_interfaces[NAL_MAX_NR];
int               ptlrpc_ninterfaces;

/*  
 *  Client's outgoing request callback
 */
void request_out_callback(ptl_event_t *ev)
{
        struct ptlrpc_cb_id   *cbid = ev->mem_desc.user_ptr;
        struct ptlrpc_request *req = cbid->cbid_arg;
        unsigned long          flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_SENT ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT (ev->unlinked);

        DEBUG_REQ((ev->status == PTL_OK) ? D_NET : D_ERROR, req,
                  "type %d, status %d", ev->type, ev->status);

        if (ev->type == PTL_EVENT_UNLINK ||
            ev->status != PTL_OK) {

                /* Failed send: make it seem like the reply timed out, just
                 * like failing sends in client.c does currently...  */

                spin_lock_irqsave(&req->rq_lock, flags);
                req->rq_timeout = 0;
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
        struct ptlrpc_cb_id   *cbid = ev->mem_desc.user_ptr;
        struct ptlrpc_request *req = cbid->cbid_arg;
        unsigned long flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_PUT ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT (ev->unlinked);
        LASSERT (ev->mem_desc.start == req->rq_repmsg);
        LASSERT (ev->offset == 0);
        LASSERT (ev->mlength <= req->rq_replen);
        
        DEBUG_REQ((ev->status == PTL_OK) ? D_NET : D_ERROR, req,
                  "type %d, status %d", ev->type, ev->status);

        spin_lock_irqsave (&req->rq_lock, flags);

        LASSERT (req->rq_receiving_reply);
        req->rq_receiving_reply = 0;

        if (ev->type == PTL_EVENT_PUT &&
            ev->status == PTL_OK) {
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
        struct ptlrpc_cb_id     *cbid = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_desc *desc = cbid->cbid_arg;
        unsigned long            flags;
        ENTRY;

        LASSERT ((desc->bd_type == BULK_PUT_SINK && 
                  ev->type == PTL_EVENT_PUT) ||
                 (desc->bd_type == BULK_GET_SOURCE &&
                  ev->type == PTL_EVENT_GET) ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT (ev->unlinked);

        CDEBUG((ev->status == PTL_OK) ? D_NET : D_ERROR,
               "event type %d, status %d, desc %p\n", 
               ev->type, ev->status, desc);

        spin_lock_irqsave (&desc->bd_lock, flags);

        LASSERT(desc->bd_network_rw);
        desc->bd_network_rw = 0;

        if (ev->type != PTL_EVENT_UNLINK &&
            ev->status == PTL_OK) {
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
        struct ptlrpc_cb_id               *cbid = ev->mem_desc.user_ptr;
        struct ptlrpc_request_buffer_desc *rqbd = cbid->cbid_arg;
        struct ptlrpc_srv_ni              *srv_ni = rqbd->rqbd_srv_ni;
        struct ptlrpc_service             *service = srv_ni->sni_service;
        struct ptlrpc_request             *req;
        long                               flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_PUT ||
                 ev->type == PTL_EVENT_UNLINK);
        LASSERT ((char *)ev->mem_desc.start >= rqbd->rqbd_buffer);
        LASSERT ((char *)ev->mem_desc.start + ev->offset + ev->mlength <=
                 rqbd->rqbd_buffer + service->srv_buf_size);

        CDEBUG((ev->status == PTL_OK) ? D_NET : D_ERROR,
               "event type %d, status %d, service %s\n", 
               ev->type, ev->status, service->srv_name);

        if (ev->unlinked) {
                /* If this is the last request message to fit in the
                 * request buffer we can use the request object embedded in
                 * rqbd.  Note that if we failed to allocate a request,
                 * we'd have to re-post the rqbd, which we can't do in this
                 * context. */
                req = &rqbd->rqbd_req;
                memset(req, 0, sizeof (*req));
        } else {
                LASSERT (ev->type == PTL_EVENT_PUT);
                if (ev->status != PTL_OK) {
                        /* We moaned above already... */
                        return;
                }
                OBD_ALLOC_GFP(req, sizeof(*req), GFP_ATOMIC);
                if (req == NULL) {
                        CERROR("Can't allocate incoming request descriptor: "
                               "Dropping %s RPC from "LPX64"\n",
                               service->srv_name, ev->initiator.nid);
                        return;
                }
        }

        /* NB we ABSOLUTELY RELY on req being zeroed, so pointers are NULL,
         * flags are reset and scalars are zero.  We only set the message
         * size to non-zero if this was a successful receive. */
        req->rq_xid = ev->match_bits;
        req->rq_reqmsg = ev->mem_desc.start + ev->offset;
        if (ev->type == PTL_EVENT_PUT &&
            ev->status == PTL_OK)
                req->rq_reqlen = ev->mlength;
        req->rq_arrival_time = ev->arrival_time;
        req->rq_peer.peer_nid = ev->initiator.nid;
        req->rq_peer.peer_ni = rqbd->rqbd_srv_ni->sni_ni;
        req->rq_rqbd = rqbd;

        spin_lock_irqsave (&service->srv_lock, flags);

        if (ev->unlinked) {
                srv_ni->sni_nrqbd_receiving--;
                if (ev->type != PTL_EVENT_UNLINK &&
                    srv_ni->sni_nrqbd_receiving == 0) {
                        /* This service is off-air on this interface because
                         * all its request buffers are busy.  Portals will
                         * start dropping incoming requests until more buffers
                         * get posted.  NB don't moan if it's because we're
                         * tearing down the service. */
                        CWARN("All %s %s request buffers busy\n",
                              service->srv_name, srv_ni->sni_ni->pni_name);
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
        struct ptlrpc_cb_id       *cbid = ev->mem_desc.user_ptr;
        struct ptlrpc_reply_state *rs = cbid->cbid_arg;
        struct ptlrpc_srv_ni      *sni = rs->rs_srv_ni;
        struct ptlrpc_service     *svc = sni->sni_service;
        unsigned long              flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_SENT ||
                 ev->type == PTL_EVENT_ACK ||
                 ev->type == PTL_EVENT_UNLINK);

        if (!rs->rs_difficult) {
                /* I'm totally responsible for freeing "easy" replies */
                LASSERT (ev->unlinked);
                lustre_free_reply_state (rs);
                atomic_dec (&svc->srv_outstanding_replies);
                EXIT;
                return;
        }

        LASSERT (rs->rs_on_net);

        if (ev->unlinked) {
                /* Last network callback */
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
        struct ptlrpc_cb_id     *cbid = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_desc *desc = cbid->cbid_arg;
        unsigned long            flags;
        ENTRY;

        LASSERT (ev->type == PTL_EVENT_SENT ||
                 ev->type == PTL_EVENT_UNLINK ||
                 (desc->bd_type == BULK_PUT_SOURCE &&
                  ev->type == PTL_EVENT_ACK) ||
                 (desc->bd_type == BULK_GET_SINK &&
                  ev->type == PTL_EVENT_REPLY));

        CDEBUG((ev->status == PTL_OK) ? D_NET : D_ERROR,
               "event type %d, status %d, desc %p\n", 
               ev->type, ev->status, desc);

        spin_lock_irqsave (&desc->bd_lock, flags);
        
        if ((ev->type == PTL_EVENT_ACK ||
             ev->type == PTL_EVENT_REPLY) &&
            ev->status == PTL_OK) {
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

static int ptlrpc_master_callback(ptl_event_t *ev)
{
        struct ptlrpc_cb_id *cbid = ev->mem_desc.user_ptr;
        void (*callback)(ptl_event_t *ev) = cbid->cbid_fn;

        /* Honestly, it's best to find out early. */
        LASSERT (cbid->cbid_arg != (void *)0x5a5a5a5a5a5a5a5a);
        LASSERT (callback == request_out_callback ||
                 callback == reply_in_callback ||
                 callback == client_bulk_callback ||
                 callback == request_in_callback ||
                 callback == reply_out_callback ||
                 callback == server_bulk_callback);
        
        callback (ev);
        return (0);
}

int ptlrpc_uuid_to_peer (struct obd_uuid *uuid, struct ptlrpc_peer *peer)
{
        struct ptlrpc_ni   *pni;
        struct lustre_peer  lpeer;
        int                 i;
        int                 rc = lustre_uuid_to_peer (uuid->uuid, &lpeer);

        if (rc != 0)
                RETURN (rc);

        for (i = 0; i < ptlrpc_ninterfaces; i++) {
                pni = &ptlrpc_interfaces[i];

                if (!memcmp(&lpeer.peer_ni, &pni->pni_ni_h,
                            sizeof (lpeer.peer_ni))) {
                        peer->peer_nid = lpeer.peer_nid;
                        peer->peer_ni = pni;
                        return (0);
                }
        }

        CERROR("Can't find ptlrpc interface for "LPX64" ni handle %08lx."LPX64"\n",
               lpeer.peer_nid, lpeer.peer_ni.nal_idx, lpeer.peer_ni.cookie);
        return (-ENOENT);
}

void ptlrpc_ni_fini(struct ptlrpc_ni *pni)
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
                rc = PtlEQFree(pni->pni_eq_h);
                switch (rc) {
                default:
                        LBUG();

                case PTL_OK:
                        kportal_put_ni (pni->pni_number);
                        return;
                        
                case PTL_EQ_INUSE:
                        if (retries != 0)
                                CWARN("Event queue for %s still busy\n",
                                      pni->pni_name);
                        
                        /* Wait for a bit */
                        init_waitqueue_head(&waitq);
                        lwi = LWI_TIMEOUT(2*HZ, NULL, NULL);
                        l_wait_event(waitq, 0, &lwi);
                        break;
                }
        }
        /* notreached */
}

int ptlrpc_ni_init(int number, char *name, struct ptlrpc_ni *pni)
{
        int              rc;
        ptl_handle_ni_t *nip = kportal_get_ni (number);

        if (nip == NULL) {
                CDEBUG (D_NET, "Network interface %s not loaded\n", name);
                return (-ENOENT);
        }

        CDEBUG (D_NET, "init %d %s: nal_idx %ld\n", number, name, nip->nal_idx);

        pni->pni_name = name;
        pni->pni_number = number;
        pni->pni_ni_h = *nip;

        pni->pni_eq_h = PTL_HANDLE_NONE;

#ifdef __KERNEL__
        /* kernel: portals calls the callback when the event is added to the
         * queue, so we don't care if we lose events */
        rc = PtlEQAlloc(pni->pni_ni_h, 1024, ptlrpc_master_callback,
                        &pni->pni_eq_h);
#else
        /* liblustre: no asynchronous callback and allocate a nice big event
         * queue so we don't drop any events... */
        rc = PtlEQAlloc(pni->pni_ni_h, 10240, NULL, &pni->pni_eq_h);
#endif
        if (rc != PTL_OK)
                GOTO (fail, rc = -ENOMEM);

        return (0);
 fail:
        CERROR ("Failed to initialise network interface %s: %d\n",
                name, rc);

        /* OK to do complete teardown since we invalidated the handles above */
        ptlrpc_ni_fini (pni);
        return (rc);
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
        ENTRY;

        if (timeout) {
                rc = PtlEQWait_timeout(ptlrpc_interfaces[0].pni_eq_h, &ev, timeout);
        } else {
                rc = PtlEQGet (ptlrpc_interfaces[0].pni_eq_h, &ev);
        }
        if (rc == PTL_EQ_EMPTY)
                RETURN(0);
        
        LASSERT (rc == PTL_EQ_DROPPED || rc == PTL_OK);
        
#ifndef __KERNEL__
        /* liblustre: no asynch callback so we can't affort to miss any
         * events... */
        if (rc == PTL_EQ_DROPPED) {
                CERROR ("Dropped an event!!!\n");
                abort();
        }
        
        ptlrpc_master_callback (&ev);
#endif
        RETURN(1);
}

int
liblustre_wait_event (int timeout)
{
        struct list_head               *tmp;
        struct liblustre_wait_callback *llwc;
        int                             found_something = 0;

        /* First check for any new events */
        if (liblustre_check_events(0))
                found_something = 1;

        /* Now give all registered callbacks a bite at the cherry */
        list_for_each(tmp, &liblustre_wait_callbacks) {
                llwc = list_entry(tmp, struct liblustre_wait_callback, 
                                  llwc_list);
                
                if (llwc->llwc_fn(llwc->llwc_arg))
                        found_something = 1;
        }

        /* return to caller if something happened */
        if (found_something)
                return 1;
        
        /* block for an event, returning immediately on timeout */
        if (!liblustre_check_events(timeout))
                return 0;

        /* an event occurred; let all registered callbacks progress... */
        list_for_each(tmp, &liblustre_wait_callbacks) {
                llwc = list_entry(tmp, struct liblustre_wait_callback, 
                                  llwc_list);
                
                if (llwc->llwc_fn(llwc->llwc_arg))
                        found_something = 1;
        }

        /* ...and tell caller something happened */
        return 1;
}
#endif

int ptlrpc_init_portals(void)
{
        /* Add new portals network interfaces here.
         * Order is irrelevent! */
        static struct {
                int   number;
                char *name;
        } ptl_nis[] = {
                {QSWNAL,  "qswnal"},
                {SOCKNAL, "socknal"},
                {GMNAL,   "gmnal"},
                {IBNAL,   "ibnal"},
                {TCPNAL,  "tcpnal"},
                {SCIMACNAL, "scimacnal"}};
        int   rc;
        int   i;

        LASSERT(ptlrpc_ninterfaces == 0);

        for (i = 0; i < sizeof (ptl_nis) / sizeof (ptl_nis[0]); i++) {
                LASSERT(ptlrpc_ninterfaces < (sizeof(ptlrpc_interfaces) /
                                              sizeof(ptlrpc_interfaces[0])));

                rc = ptlrpc_ni_init(ptl_nis[i].number, ptl_nis[i].name,
                                    &ptlrpc_interfaces[ptlrpc_ninterfaces]);
                if (rc == 0)
                        ptlrpc_ninterfaces++;
        }

        if (ptlrpc_ninterfaces == 0) {
                CERROR("network initialisation failed: is a NAL module "
                       "loaded?\n");
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
        while (ptlrpc_ninterfaces > 0)
                ptlrpc_ni_fini (&ptlrpc_interfaces[--ptlrpc_ninterfaces]);
}
