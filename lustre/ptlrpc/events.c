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
 *  Free the packet when it has gone out
 */
static int request_out_callback(ptl_event_t *ev)
{
        struct ptlrpc_request *req = ev->mem_desc.user_ptr;
        ENTRY;

        /* requests always contiguous */
        LASSERT((ev->mem_desc.options & (PTL_MD_IOV | PTL_MD_KIOV)) == 0);

        if (ev->type != PTL_EVENT_SENT) {
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        /* this balances the atomic_inc in ptl_send_rpc() */
        ptlrpc_req_finished(req);
        RETURN(1);
}

/*
 *  Free the packet when it has gone out
 */
static int reply_out_callback(ptl_event_t *ev)
{
        struct ptlrpc_request *req = ev->mem_desc.user_ptr;
        unsigned long          flags;
        ENTRY;

        /* replies always contiguous */
        LASSERT((ev->mem_desc.options & (PTL_MD_IOV | PTL_MD_KIOV)) == 0);

        if (ev->type == PTL_EVENT_SENT) {
                /* NB don't even know if this is the current reply! In fact
                 * we can't touch any state in the request, since the
                 * service handler zeros it on each incoming request. */
                OBD_FREE(ev->mem_desc.start, ev->mem_desc.length);
        } else if (ev->type == PTL_EVENT_ACK) {
                LASSERT(req->rq_want_ack);
                spin_lock_irqsave(&req->rq_lock, flags);
                req->rq_want_ack = 0;
                wake_up(&req->rq_reply_waitq);
                spin_unlock_irqrestore(&req->rq_lock, flags);
        } else {
                // XXX make sure we understand all events
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        RETURN(1);
}

/*
 * Wake up the thread waiting for the reply once it comes in.
 */
int reply_in_callback(ptl_event_t *ev)
{
        struct ptlrpc_request *req = ev->mem_desc.user_ptr;
        unsigned long flags;
        ENTRY;

        /* replies always contiguous */
        LASSERT((ev->mem_desc.options & (PTL_MD_IOV | PTL_MD_KIOV)) == 0);

        if (req->rq_xid == 0x5a5a5a5a5a5a5a5aULL) {
                CERROR("Reply received for freed request!  Probably a missing "
                       "ptlrpc_abort()\n");
                LBUG();
        }

        if (req->rq_xid != ev->match_bits) {
                CERROR("Reply packet for wrong request\n");
                LBUG();
        }

        if (ev->type == PTL_EVENT_PUT) {
                /* Bug 1190: should handle non-zero offset as a protocol
                 * error  */
                LASSERT (ev->offset == 0);

                spin_lock_irqsave (&req->rq_lock, flags);
                LASSERT (req->rq_receiving_reply);
                req->rq_receiving_reply = 0;
                req->rq_replied = 1;
                if (req->rq_set != NULL)
                        wake_up(&req->rq_set->set_waitq);
                else
                        wake_up(&req->rq_reply_waitq);
                spin_unlock_irqrestore (&req->rq_lock, flags);
        } else {
                // XXX make sure we understand all events, including ACKs
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        RETURN(1);
}

int request_in_callback(ptl_event_t *ev)
{
        struct ptlrpc_request_buffer_desc *rqbd = ev->mem_desc.user_ptr;
        struct ptlrpc_srv_ni  *srv_ni = rqbd->rqbd_srv_ni;
        struct ptlrpc_service *service = srv_ni->sni_service;

        /* requests always contiguous */
        LASSERT((ev->mem_desc.options & (PTL_MD_IOV | PTL_MD_KIOV)) == 0);
        /* we only enable puts */
        LASSERT(ev->type == PTL_EVENT_PUT);
        LASSERT(atomic_read(&srv_ni->sni_nrqbds_receiving) > 0);
        LASSERT(atomic_read(&rqbd->rqbd_refcount) > 0);

        if (ev->rlength != ev->mlength)
                CERROR("Warning: Possibly truncated rpc (%d/%d)\n",
                       ev->mlength, ev->rlength);

        if (!PtlHandleEqual (ev->unlinked_me, PTL_HANDLE_NONE)) {
                /* This is the last request to be received into this
                 * request buffer.  We don't bump the refcount, since the
                 * thread servicing this event is effectively taking over
                 * portals' reference.
                 */
                /* NB ev->unlinked_me.nal_idx is not set properly in a callback */
                LASSERT(ev->unlinked_me.cookie==rqbd->rqbd_me_h.cookie);

                /* we're off the air */
                /* we'll probably start dropping packets in portals soon */
                if (atomic_dec_and_test(&srv_ni->sni_nrqbds_receiving))
                        CERROR("All request buffers busy\n");
        } else {
                /* +1 ref for service thread */
                atomic_inc(&rqbd->rqbd_refcount);
        }

        wake_up(&service->srv_waitq);

        return 0;
}

static int bulk_put_source_callback(ptl_event_t *ev)
{
        unsigned long            flags;
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        ENTRY;

        CDEBUG(D_NET, "got %s event %d\n",
               (ev->type == PTL_EVENT_SENT) ? "SENT" :
               (ev->type == PTL_EVENT_ACK)  ? "ACK"  : "UNEXPECTED", ev->type);

        LASSERT(ev->type == PTL_EVENT_SENT || ev->type == PTL_EVENT_ACK);

        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);

        spin_lock_irqsave (&desc->bd_lock, flags);
        
        LASSERT(desc->bd_callback_count > 0 &&
                desc->bd_callback_count <= 2);
        
        if (--desc->bd_callback_count == 0) {
                desc->bd_network_rw = 0;
                desc->bd_complete = 1;
                wake_up(&desc->bd_waitq);
        }

        spin_unlock_irqrestore (&desc->bd_lock, flags);
        RETURN(0);
}

struct ptlrpc_bulk_desc ptlrpc_bad_desc;
ptl_event_t ptlrpc_bad_event;

static int bulk_put_sink_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        unsigned long            flags;
        ENTRY;

        LASSERT(ev->type == PTL_EVENT_PUT);

        /* used iovs */
        LASSERT((ev->mem_desc.options & (PTL_MD_IOV | PTL_MD_KIOV)) ==
                PTL_MD_KIOV);
        /* Honestly, it's best to find out early. */
        if (desc->bd_page_count == 0x5a5a5a5a ||
            desc->bd_page_count != ev->mem_desc.niov ||
            ev->mem_desc.start != &desc->bd_iov) {
                /* not guaranteed (don't LASSERT) but good for this bug hunt */
                ptlrpc_bad_event = *ev;
                ptlrpc_bad_desc = *desc;
                CERROR ("XXX ev %p type %d portal %d match "LPX64", seq %ld\n",
                        ev, ev->type, ev->portal, ev->match_bits, ev->sequence);
                CERROR ("XXX desc %p, export %p import %p gen %d "
                        " portal %d\n", 
                        desc, desc->bd_export,
                        desc->bd_import, desc->bd_import_generation,
                        desc->bd_portal);
                RETURN (0);
        }
        
        LASSERT(desc->bd_page_count != 0x5a5a5a5a);
        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);
        LASSERT(ev->match_bits == desc->bd_req->rq_xid);
        
        /* peer must put with zero offset */
        if (ev->offset != 0) {
                /* Bug 1190: handle this as a protocol failure */
                CERROR ("Bad offset %d\n", ev->offset);
                LBUG ();
        }

        /* No check for total # bytes; this could be a short read */

        spin_lock_irqsave (&desc->bd_lock, flags);
        desc->bd_network_rw = 0;
        desc->bd_complete = 1;
        if (desc->bd_req->rq_set != NULL)
                wake_up (&desc->bd_req->rq_set->set_waitq);
        else
                wake_up (&desc->bd_req->rq_reply_waitq);
        spin_unlock_irqrestore (&desc->bd_lock, flags);

        RETURN(1);
}

static int bulk_get_source_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_page *bulk;
        struct list_head        *tmp;
        unsigned long            flags;
        ptl_size_t               total = 0;
        ENTRY;

        LASSERT(ev->type == PTL_EVENT_GET);

        /* used iovs */
        LASSERT((ev->mem_desc.options & (PTL_MD_IOV | PTL_MD_KIOV)) ==
                PTL_MD_KIOV);
        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);
        LASSERT(ev->match_bits == desc->bd_req->rq_xid);

        /* peer must get with zero offset */
        if (ev->offset != 0) {
                /* Bug 1190: handle this as a protocol failure */
                CERROR ("Bad offset %d\n", ev->offset);
                LBUG ();
        }
        
        list_for_each (tmp, &desc->bd_page_list) {
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                total += bulk->bp_buflen;
        }

        /* peer must get everything */
        if (ev->mem_desc.length != total) {
                /* Bug 1190: handle this as a protocol failure */
                CERROR ("Bad length/total %d/%d\n", ev->mem_desc.length, total);
                LBUG ();
        }

        spin_lock_irqsave (&desc->bd_lock, flags);
        desc->bd_network_rw = 0;
        desc->bd_complete = 1;
        if (desc->bd_req->rq_set != NULL)
                wake_up (&desc->bd_req->rq_set->set_waitq);
        else
                wake_up (&desc->bd_req->rq_reply_waitq);
        spin_unlock_irqrestore (&desc->bd_lock, flags);

        RETURN(1);
}

static int bulk_get_sink_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        unsigned long            flags;
        ENTRY;

        CDEBUG(D_NET, "got %s event %d desc %p\n",
               (ev->type == PTL_EVENT_SENT) ? "SENT" :
               (ev->type == PTL_EVENT_REPLY)  ? "REPLY"  : "UNEXPECTED",
               ev->type, desc);

        LASSERT(ev->type == PTL_EVENT_SENT || ev->type == PTL_EVENT_REPLY);

        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);

        spin_lock_irqsave (&desc->bd_lock, flags);
        LASSERT(desc->bd_callback_count > 0 &&
                desc->bd_callback_count <= 2);

        if (--desc->bd_callback_count == 0) {
                desc->bd_network_rw = 0;
                desc->bd_complete = 1;
                wake_up(&desc->bd_waitq);
        }
        spin_unlock_irqrestore (&desc->bd_lock, flags);

        RETURN(0);
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
        PtlEQFree(pni->pni_request_out_eq_h);
        PtlEQFree(pni->pni_reply_out_eq_h);
        PtlEQFree(pni->pni_reply_in_eq_h);
        PtlEQFree(pni->pni_bulk_put_source_eq_h);
        PtlEQFree(pni->pni_bulk_put_sink_eq_h);
        PtlEQFree(pni->pni_bulk_get_source_eq_h);
        PtlEQFree(pni->pni_bulk_get_sink_eq_h);

        kportal_put_ni (pni->pni_number);
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

        pni->pni_request_out_eq_h = PTL_HANDLE_NONE;
        pni->pni_reply_out_eq_h = PTL_HANDLE_NONE;
        pni->pni_reply_in_eq_h = PTL_HANDLE_NONE;
        pni->pni_bulk_put_source_eq_h = PTL_HANDLE_NONE;
        pni->pni_bulk_put_sink_eq_h = PTL_HANDLE_NONE;
        pni->pni_bulk_get_source_eq_h = PTL_HANDLE_NONE;
        pni->pni_bulk_get_sink_eq_h = PTL_HANDLE_NONE;

        /* NB We never actually PtlEQGet() out of these events queues since
         * we're only interested in the event callback, so we can just let
         * them wrap.  Their sizes aren't a big deal, apart from providing
         * a little history for debugging... */

        rc = PtlEQAlloc(pni->pni_ni_h, 1024, request_out_callback,
                        &pni->pni_request_out_eq_h);
        if (rc != PTL_OK)
                GOTO (fail, rc = -ENOMEM);

        rc = PtlEQAlloc(pni->pni_ni_h, 1024, reply_out_callback,
                        &pni->pni_reply_out_eq_h);
        if (rc != PTL_OK)
                GOTO (fail, rc = -ENOMEM);

        rc = PtlEQAlloc(pni->pni_ni_h, 1024, reply_in_callback,
                        &pni->pni_reply_in_eq_h);
        if (rc != PTL_OK)
                GOTO (fail, rc = -ENOMEM);

        rc = PtlEQAlloc(pni->pni_ni_h, 1024, bulk_put_source_callback,
                        &pni->pni_bulk_put_source_eq_h);
        if (rc != PTL_OK)
                GOTO (fail, rc = -ENOMEM);

        rc = PtlEQAlloc(pni->pni_ni_h, 1024, bulk_put_sink_callback,
                        &pni->pni_bulk_put_sink_eq_h);
        if (rc != PTL_OK)
                GOTO (fail, rc = -ENOMEM);

        rc = PtlEQAlloc(pni->pni_ni_h, 1024, bulk_get_source_callback,
                        &pni->pni_bulk_get_source_eq_h);
        if (rc != PTL_OK)
                GOTO (fail, rc = -ENOMEM);

        rc = PtlEQAlloc(pni->pni_ni_h, 1024, bulk_get_sink_callback,
                        &pni->pni_bulk_get_sink_eq_h);
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
int
liblustre_check_events (int block)
{
        ptl_event_t ev;
        int         rc;
        ENTRY;

        if (block) {
                /* XXX to accelerate recovery tests XXX */
                if (block > 10)
                        block = 10;
                rc = PtlEQWait_timeout(ptlrpc_interfaces[0].pni_eq_h, &ev, block);
        } else {
                rc = PtlEQGet (ptlrpc_interfaces[0].pni_eq_h, &ev);
        }
        if (rc == PTL_EQ_EMPTY)
                RETURN(0);
        
        LASSERT (rc == PTL_EQ_DROPPED || rc == PTL_OK);
        
#if PORTALS_DOES_NOT_SUPPORT_CALLBACKS
        if (rc == PTL_EQ_DROPPED)
                CERROR ("Dropped an event!!!\n");
        
        ptlrpc_master_callback (&ev);
#endif
        RETURN(1);
}

int liblustre_wait_event(struct l_wait_info *lwi) 
{
        ENTRY;

        /* non-blocking checks (actually we might block in a service for
         * bulk but we won't block in a blocked service)
         */
        if (liblustre_check_events(0) ||
            liblustre_check_services()) {
                /* the condition the caller is waiting for may now hold */
                RETURN(0);
        }
        
        /* block for an event */
        liblustre_check_events(lwi->lwi_timeout);

        /* check it's not for some service */
        liblustre_check_services ();

        /* XXX check this */
        RETURN(0);
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
                {TOENAL,  "toenal"},
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
        return 0;
}

void ptlrpc_exit_portals(void)
{
        while (ptlrpc_ninterfaces > 0)
                ptlrpc_ni_fini (&ptlrpc_interfaces[--ptlrpc_ninterfaces]);
}
