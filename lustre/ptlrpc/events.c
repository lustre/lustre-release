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
        LASSERT((ev->mem_desc.options & PTL_MD_IOV) == 0);

        if (ev->type != PTL_EVENT_SENT) {
                // XXX make sure we understand all events, including ACK's
                CERROR("Unknown event %d\n", ev->type);
                LBUG();
        }

        /* this balances the atomic_inc in ptl_send_rpc */
        ptlrpc_req_finished(req);
        RETURN(1);
}


/*
 *  Free the packet when it has gone out
 */
static int reply_out_callback(ptl_event_t *ev)
{
        ENTRY;

        /* replies always contiguous */
        LASSERT((ev->mem_desc.options & PTL_MD_IOV) == 0);

        if (ev->type == PTL_EVENT_SENT) {
                OBD_FREE(ev->mem_desc.start, ev->mem_desc.length);
        } else if (ev->type == PTL_EVENT_ACK) {
                struct ptlrpc_request *req = ev->mem_desc.user_ptr;
                if (req->rq_flags & PTL_RPC_FL_WANT_ACK) {
                        req->rq_flags &= ~PTL_RPC_FL_WANT_ACK;
                        wake_up(&req->rq_wait_for_rep);
                } else {
                        DEBUG_REQ(D_ERROR, req,
                                  "ack received for reply, not wanted");
                }
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
        ENTRY;

        /* replies always contiguous */
        LASSERT((ev->mem_desc.options & PTL_MD_IOV) == 0);

        if (req->rq_xid == 0x5a5a5a5a5a5a5a5a) {
                CERROR("Reply received for freed request!  Probably a missing "
                       "ptlrpc_abort()\n");
                LBUG();
        }

        if (req->rq_xid != ev->match_bits) {
                CERROR("Reply packet for wrong request\n");
                LBUG();
        }

        if (ev->type == PTL_EVENT_PUT) {
                req->rq_repmsg = ev->mem_desc.start + ev->offset;
                barrier();
                wake_up(&req->rq_wait_for_rep);
        } else {
                // XXX make sure we understand all events, including ACK's
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
        LASSERT((ev->mem_desc.options & PTL_MD_IOV) == 0);
        /* we only enable puts */
        LASSERT(ev->type == PTL_EVENT_PUT);
        LASSERT(atomic_read(&srv_ni->sni_nrqbds_receiving) > 0);
        LASSERT(atomic_read(&rqbd->rqbd_refcount) > 0);

        if (ev->rlength != ev->mlength)
                CERROR("Warning: Possibly truncated rpc (%d/%d)\n",
                       ev->mlength, ev->rlength);

        if (ptl_is_valid_handle(&ev->unlinked_me)) {
                /* This is the last request to be received into this
                 * request buffer.  We don't bump the refcount, since the
                 * thread servicing this event is effectively taking over
                 * portals' reference.
                 */
#warning ev->unlinked_me.nal_idx is not set properly in a callback
                LASSERT(ev->unlinked_me.handle_idx==rqbd->rqbd_me_h.handle_idx);

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
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_page *bulk;
        struct list_head        *tmp;
        struct list_head        *next;
        ENTRY;

        CDEBUG(D_NET, "got %s event %d\n",
               (ev->type == PTL_EVENT_SENT) ? "SENT" :
               (ev->type == PTL_EVENT_ACK)  ? "ACK"  : "UNEXPECTED", ev->type);

        LASSERT(ev->type == PTL_EVENT_SENT || ev->type == PTL_EVENT_ACK);

        LASSERT(atomic_read(&desc->bd_source_callback_count) > 0 &&
                atomic_read(&desc->bd_source_callback_count) <= 2);

        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);

        if (atomic_dec_and_test(&desc->bd_source_callback_count)) {
                void (*event_handler)(struct ptlrpc_bulk_desc *);

                list_for_each_safe(tmp, next, &desc->bd_page_list) {
                        bulk = list_entry(tmp, struct ptlrpc_bulk_page,
                                          bp_link);

                        if (bulk->bp_cb != NULL)
                                bulk->bp_cb(bulk);
                }

                /* We need to make a note of whether there's an event handler
                 * before we call wake_up, because if there is no event handler,
                 * 'desc' might be freed before we're scheduled again. */
                event_handler = desc->bd_ptl_ev_hdlr;

                desc->bd_flags |= PTL_BULK_FL_SENT;
                wake_up(&desc->bd_waitq);
                if (event_handler) {
                        LASSERT(desc->bd_ptl_ev_hdlr == event_handler);
                        event_handler(desc);
                }
        }

        RETURN(0);
}

static int bulk_put_sink_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_page *bulk;
        struct list_head        *tmp;
        struct list_head        *next;
        ptl_size_t               total = 0;
        void                   (*event_handler)(struct ptlrpc_bulk_desc *);
        ENTRY;

        LASSERT(ev->type == PTL_EVENT_PUT);

        /* put with zero offset */
        LASSERT(ev->offset == 0);
        /* used iovs */
        LASSERT((ev->mem_desc.options & PTL_MD_IOV) != 0);
        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);

        list_for_each_safe (tmp, next, &desc->bd_page_list) {
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                total += bulk->bp_buflen;

                if (bulk->bp_cb != NULL)
                        bulk->bp_cb(bulk);
        }

        LASSERT(ev->mem_desc.length == total);

        /* We need to make a note of whether there's an event handler
         * before we call wake_up, because if there is no event
         * handler, 'desc' might be freed before we're scheduled again. */
        event_handler = desc->bd_ptl_ev_hdlr;

        desc->bd_flags |= PTL_BULK_FL_RCVD;
        wake_up(&desc->bd_waitq);
        if (event_handler) {
                LASSERT(desc->bd_ptl_ev_hdlr == event_handler);
                event_handler(desc);
        }

        RETURN(1);
}

static int bulk_get_source_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_page *bulk;
        struct list_head        *tmp;
        struct list_head        *next;
        ptl_size_t               total = 0;
        void                   (*event_handler)(struct ptlrpc_bulk_desc *);
        ENTRY;

        LASSERT(ev->type == PTL_EVENT_GET);

        /* put with zero offset */
        LASSERT(ev->offset == 0);
        /* used iovs */
        LASSERT((ev->mem_desc.options & PTL_MD_IOV) != 0);
        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);

        list_for_each_safe (tmp, next, &desc->bd_page_list) {
                bulk = list_entry(tmp, struct ptlrpc_bulk_page, bp_link);

                total += bulk->bp_buflen;

                if (bulk->bp_cb != NULL)
                        bulk->bp_cb(bulk);
        }

        LASSERT(ev->mem_desc.length == total);

        /* We need to make a note of whether there's an event handler
         * before we call wake_up, because if there is no event
         * handler, 'desc' might be freed before we're scheduled again. */
        event_handler = desc->bd_ptl_ev_hdlr;

        desc->bd_flags |= PTL_BULK_FL_SENT;
        wake_up(&desc->bd_waitq);
        if (event_handler) {
                LASSERT(desc->bd_ptl_ev_hdlr == event_handler);
                event_handler(desc);
        }

        RETURN(1);
}


static int bulk_get_sink_callback(ptl_event_t *ev)
{
        struct ptlrpc_bulk_desc *desc = ev->mem_desc.user_ptr;
        struct ptlrpc_bulk_page *bulk;
        struct list_head        *tmp;
        struct list_head        *next;
        ENTRY;

        CDEBUG(D_NET, "got %s event %d\n",
               (ev->type == PTL_EVENT_SENT) ? "SENT" :
               (ev->type == PTL_EVENT_REPLY)  ? "REPLY"  : "UNEXPECTED", 
               ev->type);

        LASSERT(ev->type == PTL_EVENT_SENT || ev->type == PTL_EVENT_REPLY);

        LASSERT(atomic_read(&desc->bd_source_callback_count) > 0 &&
                atomic_read(&desc->bd_source_callback_count) <= 2);

        /* 1 fragment for each page always */
        LASSERT(ev->mem_desc.niov == desc->bd_page_count);

        if (atomic_dec_and_test(&desc->bd_source_callback_count)) {
                void (*event_handler)(struct ptlrpc_bulk_desc *);

                list_for_each_safe(tmp, next, &desc->bd_page_list) {
                        bulk = list_entry(tmp, struct ptlrpc_bulk_page,
                                          bp_link);

                        if (bulk->bp_cb != NULL)
                                bulk->bp_cb(bulk);
                }

                /* We need to make a note of whether there's an event handler
                 * before we call wake_up, because if there is no event handler,
                 * 'desc' might be freed before we're scheduled again. */
                event_handler = desc->bd_ptl_ev_hdlr;

                desc->bd_flags |= PTL_BULK_FL_RCVD;
                wake_up(&desc->bd_waitq);
                if (event_handler) {
                        LASSERT(desc->bd_ptl_ev_hdlr == event_handler);
                        event_handler(desc);
                }
        }

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

                if (!memcmp (&lpeer.peer_ni, &pni->pni_ni_h,
                             sizeof (lpeer.peer_ni))) {
                        peer->peer_nid = lpeer.peer_nid;
                        peer->peer_ni = pni;
                        return (0);
                }
        }
        
        CERROR ("Can't find ptlrpc interface for "LPX64" ni handle %08lx %08lx\n",
                lpeer.peer_nid, lpeer.peer_ni.nal_idx, lpeer.peer_ni.handle_idx);
        return (-ENOENT);
}

void ptlrpc_ni_fini (struct ptlrpc_ni *pni) 
{
        PtlEQFree(pni->pni_request_out_eq_h);
        PtlEQFree(pni->pni_reply_out_eq_h);
        PtlEQFree(pni->pni_reply_in_eq_h);
        PtlEQFree(pni->pni_bulk_put_source_eq_h);
        PtlEQFree(pni->pni_bulk_put_sink_eq_h);
        PtlEQFree(pni->pni_bulk_get_source_eq_h);
        PtlEQFree(pni->pni_bulk_get_sink_eq_h);
        
        inter_module_put(pni->pni_name);
}

int ptlrpc_ni_init (char *name, struct ptlrpc_ni *pni) 
{
        int              rc;
        ptl_handle_ni_t *nip;

        nip = (ptl_handle_ni_t *)inter_module_get (name);
        if (nip == NULL) {
                CDEBUG (D_NET, "Network interface %s not loaded\n", name);
                return (-ENOENT);
        }
        
        CDEBUG (D_NET, "init %s: nal_idx %ld\n", name, nip->nal_idx);
                
        pni->pni_name = name;
        pni->pni_ni_h = *nip;

        ptl_set_inv_handle (&pni->pni_request_out_eq_h);
        ptl_set_inv_handle (&pni->pni_reply_out_eq_h);
        ptl_set_inv_handle (&pni->pni_reply_in_eq_h);
        ptl_set_inv_handle (&pni->pni_bulk_put_source_eq_h);
        ptl_set_inv_handle (&pni->pni_bulk_put_sink_eq_h);
        ptl_set_inv_handle (&pni->pni_bulk_get_source_eq_h);
        ptl_set_inv_handle (&pni->pni_bulk_get_sink_eq_h);
        
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

        /* OK to do complete teardown since we invalidated the handles above... */
        ptlrpc_ni_fini (pni);
        return (rc);
}

int ptlrpc_init_portals(void)
{
        /* Add new portals network interface names here.
         * Order is irrelevent! */
        char *ni_names[] = { "kqswnal_ni",
                             "kgmnal_ni",
                             "ksocknal_ni",
                             "ktoenal_ni",
                             "tcpnal_ni",
                             NULL };
        int   rc;
        int   i;
        
        LASSERT (ptlrpc_ninterfaces == 0);

        for (i = 0; ni_names[i] != NULL; i++) {
                LASSERT (ptlrpc_ninterfaces < 
                         sizeof (ptlrpc_interfaces)/sizeof (ptlrpc_interfaces[0]));
                
                rc = ptlrpc_ni_init (ni_names[i],
                                     &ptlrpc_interfaces[ptlrpc_ninterfaces]);
                if (rc == 0)
                        ptlrpc_ninterfaces++;
        }
        
        if (ptlrpc_ninterfaces == 0) {
                CERROR("network initialisation failed: is a NAL module loaded?\n");
                return -EIO;
        }
        return 0;
}

void ptlrpc_exit_portals(void)
{
        while (ptlrpc_ninterfaces > 0)
                ptlrpc_ni_fini (&ptlrpc_interfaces[--ptlrpc_ninterfaces]);
}
