/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals
 *   http://sourceforge.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <lnet/lib-lnet.h>

#ifdef __KERNEL__

static int forwarding = 0;
CFS_MODULE_PARM(forwarding, "i", int, 0444,
                "Boolean: set non-zero to forward between networks");

static int tiny_router_buffers = 512;
CFS_MODULE_PARM(tiny_router_buffers, "i", int, 0444,
                "# of 0 payload messages to buffer in the router");
static int small_router_buffers = 256;
CFS_MODULE_PARM(small_router_buffers, "i", int, 0444,
                "# of small (1 page) messages to buffer in the router");
static int large_router_buffers = 16;
CFS_MODULE_PARM(large_router_buffers, "i", int, 0444,
                "# of large messages to buffer in the router");

typedef struct
{
        work_struct_t           kpru_tq;
        lnet_nid_t              kpru_nid;
        int                     kpru_alive;
        time_t                  kpru_when;
} kpr_upcall_t;

void
kpr_do_upcall (void *arg)
{
        kpr_upcall_t *u = (kpr_upcall_t *)arg;
        char          nidstr[36];
        char          whenstr[36];
        char         *argv[] = {
                NULL,
                "ROUTER_NOTIFY",
                nidstr,
                u->kpru_alive ? "up" : "down",
                whenstr,
                NULL};

        snprintf (nidstr, sizeof(nidstr), "%s", libcfs_nid2str(u->kpru_nid));
        snprintf (whenstr, sizeof(whenstr), "%ld", u->kpru_when);

        libcfs_run_upcall (argv);

        PORTAL_FREE(u, sizeof(*u));
}

void
kpr_upcall (lnet_nid_t gw_nid, int alive, time_t when)
{
        /* May be in arbitrary context */
        kpr_upcall_t  *u;

        PORTAL_ALLOC_ATOMIC(u, sizeof(*u));
        if (u == NULL) {
                CERROR ("Upcall out of memory: nid %s %s\n",
                        libcfs_nid2str(gw_nid), alive ? "up" : "down");
                return;
        }

        u->kpru_nid        = gw_nid;
        u->kpru_alive      = alive;
        u->kpru_when       = when;

        prepare_work (&u->kpru_tq, kpr_do_upcall, u);
        schedule_work (&u->kpru_tq);
}

int
lnet_notify (lnet_ni_t *ni, lnet_nid_t gateway_nid, int alive, time_t when)
{
        lnet_peer_t         *lp = NULL;
        struct timeval       now;

        CDEBUG (D_NET, "%s notifying %s: %s\n", 
                (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
                libcfs_nid2str(gateway_nid),
                alive ? "up" : "down");
        
        if (ni != NULL &&
            PTL_NIDNET(ni->ni_nid) != PTL_NIDNET(gateway_nid)) {
                CWARN ("Ignoring notification of %s %s by %s (different net)\n",
                        libcfs_nid2str(gateway_nid), alive ? "birth" : "death",
                        libcfs_nid2str(ni->ni_nid));
                return -EINVAL;
        }
        
        /* can't do predictions... */
        do_gettimeofday (&now);
        if (when > now.tv_sec) {
                CWARN ("Ignoring prediction from %s of %s %s "
                       "%ld seconds in the future\n", 
                       (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
                       libcfs_nid2str(gateway_nid), alive ? "up" : "down", 
                       when - now.tv_sec);
                return -EINVAL;
        }

        LNET_LOCK();
        
        lp = lnet_find_peer_locked(gateway_nid);
        if (lp == NULL) {
                /* gateway not found */
                LNET_UNLOCK();
                CDEBUG (D_NET, "Gateway not found\n");
                return (0);
        }
        
        if (when < lp->lp_timestamp) {
                /* out of date information */
                lnet_peer_decref_locked(lp);
                LNET_UNLOCK();
                CDEBUG (D_NET, "Out of date\n");
                return (0);
        }

        /* update timestamp */
        lp->lp_timestamp = when;

        if ((!lp->lp_alive) == (!alive)) {
                /* new date for old news */
                lnet_peer_decref_locked(lp);
                LNET_UNLOCK();
                CDEBUG (D_NET, "Old news\n");
                return (0);
        }

        lp->lp_alive = alive;

        LNET_UNLOCK();
        
        CDEBUG(D_NET, "set %s %d\n", libcfs_nid2str(gateway_nid), alive);

        if (ni == NULL) {
                /* userland notified me: notify NAL? */
                ni = lp->lp_ni;
                if (ni->ni_lnd->lnd_notify != NULL) {
                        ni->ni_lnd->lnd_notify(ni, gateway_nid, alive);
                }
        } else {
                /* It wasn't userland that notified me... */
                LBUG(); /* LND notification disabled for now */
                CWARN ("Upcall: NID %s is %s\n",
                       libcfs_nid2str(gateway_nid),
                       alive ? "alive" : "dead");
                kpr_upcall (gateway_nid, alive, when);
        }

        LNET_LOCK();
        lnet_peer_decref_locked(lp);
        LNET_UNLOCK();

        return (0);
}
EXPORT_SYMBOL(lnet_notify);

#else

int
lnet_notify (lnet_ni_t *ni, lnet_nid_t gateway_nid, int alive, time_t when)
{
        return -EOPNOTSUPP;
}

#endif

lnet_remotenet_t *
lnet_find_net_locked (__u32 net) 
{
        lnet_remotenet_t *rnet;
        struct list_head *tmp;

        LASSERT (!the_lnet.ln_shutdown);
        
        list_for_each (tmp, &the_lnet.ln_remote_nets) {
                rnet = list_entry(tmp, lnet_remotenet_t, lrn_list);
                
                if (rnet->lrn_net == net)
                        return rnet;
        }
        return NULL;
}

int
lnet_distance (lnet_nid_t nid, int *orderp)
{
	struct list_head *e;
        lnet_remotenet_t *rnet;
        __u32             net = PTL_NIDNET(nid);
        int               dist = -ENETUNREACH;
        int               order = 0;

        if (lnet_islocalnet(net, orderp))
                return 0;

        LNET_LOCK();

        list_for_each (e, &the_lnet.ln_remote_nets) {
		rnet = list_entry(e, lnet_remotenet_t, lrn_list);

                if (rnet->lrn_net == net) {
                        dist = rnet->lrn_hops;
                        if (orderp != NULL)
                                *orderp = order;
                        break;
                }
                order++;
        }

        LNET_UNLOCK();
        return dist;
}

int
lnet_add_route (__u32 net, unsigned int hops, lnet_nid_t gateway)
{
	struct list_head    *e;
	lnet_remotenet_t    *rnet;
	lnet_remotenet_t    *rnet2;
	lnet_route_t        *route;
	lnet_route_t        *route2;
        lnet_peer_t         *lp;
        int                  dup;
        int                  hops2;
        __u32                net2;
        int                  rc;

        CDEBUG(D_WARNING, "Add route: net %s hops %u gw %s\n",
               libcfs_net2str(net), hops, libcfs_nid2str(gateway));

        if (gateway == LNET_NID_ANY ||
            hops < 1 || hops > 255)
                return (-EINVAL);

        if (lnet_islocalnet(net, NULL))         /* it's a local network */
                return 0;                       /* ignore the route entry */

        /* Assume net, route, all new */
        PORTAL_ALLOC(route, sizeof(*route));
        PORTAL_ALLOC(rnet, sizeof(*rnet));
        if (route == NULL || rnet == NULL) {
                CERROR("Out of memory creating route %s %d %s\n", 
                       libcfs_net2str(net), hops, libcfs_nid2str(gateway));
                if (route != NULL)
                        PORTAL_FREE(route, sizeof(*route));
                if (rnet != NULL)
                        PORTAL_FREE(rnet, sizeof(*rnet));
                return -ENOMEM;
        }

        LNET_LOCK();

        rc = lnet_nid2peer_locked(&lp, gateway);
        if (rc != 0) {
                LNET_UNLOCK();

                PORTAL_FREE(route, sizeof(*route));
                PORTAL_FREE(rnet, sizeof(*rnet));

                if (rc == -EHOSTUNREACH)        /* gateway is not on a local net */
                        return 0;               /* ignore the route entry */

                CERROR("Error %d creating route %s %d %s\n", rc, 
                       libcfs_net2str(net), hops, libcfs_nid2str(gateway));
                return rc;
        }

        LASSERT (!the_lnet.ln_shutdown);
        
        rnet2 = lnet_find_net_locked(net);
        if (rnet2 == NULL) {
                /* new network */
                INIT_LIST_HEAD(&rnet->lrn_routes);
                rnet->lrn_net = net;
                rnet->lrn_hops = hops;
                rnet->lrn_ni = lp->lp_ni;

                lnet_ni_addref_locked(rnet->lrn_ni);

                list_add_tail(&rnet->lrn_list, &the_lnet.ln_remote_nets);

                route->lr_gateway = lp;
                list_add_tail(&route->lr_list, &rnet->lrn_routes);

                the_lnet.ln_remote_nets_version++;
                LNET_UNLOCK();
                return 0;
        }

        hops2 = rnet2->lrn_hops;
        net2 = PTL_NIDNET(rnet2->lrn_ni->ni_nid);
        
        if (rnet2->lrn_ni == lp->lp_ni && hops2 == hops) {
                /* New route consistent with existing routes; search for
                 * duplicate route (NOOP if this is) */
                dup = 0;
                list_for_each (e, &rnet2->lrn_routes) {
                        route2 = list_entry(e, lnet_route_t, lr_list);

                        if (route2->lr_gateway->lp_nid == gateway) {
                                dup = 1;
                                break;
                        }
                }
                
                if (!dup) {
                        /* New route */
                        list_add_tail(&route->lr_list, &rnet2->lrn_routes);
                        the_lnet.ln_remote_nets_version++;
                } else {
                        lnet_peer_decref_locked(lp);
                }
                
                LNET_UNLOCK();

                PORTAL_FREE(rnet, sizeof(*rnet));
                if (dup)
                        PORTAL_FREE(route, sizeof(*route));

                return 0;
        }

        lnet_peer_decref_locked(lp);
        LNET_UNLOCK();
        PORTAL_FREE(rnet, sizeof(*rnet));
        PORTAL_FREE(route, sizeof(*route));

        if (hops != hops2)
                CERROR("Hopcount not consistent on route: %s %d(%d) %s\n",
                       libcfs_net2str(net), hops, hops2,
                       libcfs_nid2str(gateway));
        else 
                CERROR("Router network not consistent on route: %s %d %s(%s)\n",
                       libcfs_net2str(net), hops, 
                       libcfs_nid2str(gateway), libcfs_net2str(net2));
        return -EINVAL;
}

int
lnet_del_route (__u32 net, lnet_nid_t gw_nid)
{
        lnet_remotenet_t    *rnet;
        lnet_route_t        *route;
        struct list_head    *e1;
        struct list_head    *e2;
        int                  rc = -ENOENT;

        CDEBUG(D_WARNING, "Del route: net %s : gw %s\n",
               libcfs_net2str(net), libcfs_nid2str(gw_nid));

        /* NB Caller may specify either all routes via the given gateway
         * or a specific route entry actual NIDs) */

 again:
        LNET_LOCK();

        list_for_each (e1, &the_lnet.ln_remote_nets) {
                rnet = list_entry(e1, lnet_remotenet_t, lrn_list);
                
                if (!(net == PTL_NIDNET(LNET_NID_ANY) ||
                      net == rnet->lrn_net))
                        continue;
                
                list_for_each (e2, &rnet->lrn_routes) {
                        route = list_entry(e2, lnet_route_t, 
                                        lr_list);
                        
                        if (!(gw_nid == LNET_NID_ANY ||
                              gw_nid == route->lr_gateway->lp_nid))
                                continue;

                        list_del(&route->lr_list);
                        the_lnet.ln_remote_nets_version++;

                        if (list_empty(&rnet->lrn_routes))
                                list_del(&rnet->lrn_list);
                        else
                                rnet = NULL;
                        
                        lnet_peer_decref_locked(route->lr_gateway);
                        LNET_UNLOCK();

                        PORTAL_FREE(route, sizeof (*route));
                        
                        if (rnet != NULL) {
                                lnet_ni_decref(rnet->lrn_ni);
                                PORTAL_FREE(rnet, sizeof(*rnet));
                        }
                        
                        rc = 0;
                        goto again;
                }
        }

        LNET_UNLOCK();
        return rc;
}

void
lnet_destroy_routes (void)
{
        lnet_del_route(PTL_NIDNET(LNET_NID_ANY), LNET_NID_ANY);
}

int
lnet_get_route (int idx, __u32 *net, __u32 *hops, 
               lnet_nid_t *gateway, __u32 *alive)
{
	struct list_head    *e1;
	struct list_head    *e2;
        lnet_remotenet_t    *rnet;
        lnet_route_t        *route;

        LNET_LOCK();

        list_for_each (e1, &the_lnet.ln_remote_nets) {
                rnet = list_entry(e1, lnet_remotenet_t, lrn_list);
                
                list_for_each (e2, &rnet->lrn_routes) {
                        route = list_entry(e2, lnet_route_t, lr_list);
                
                        if (idx-- == 0) {
                                *net     = rnet->lrn_net;
                                *hops    = rnet->lrn_hops;
                                *gateway = route->lr_gateway->lp_nid;
                                *alive   = route->lr_gateway->lp_alive;
                                LNET_UNLOCK();
                                return 0;
                        }
                }
        }
        
        LNET_UNLOCK();
        return -ENOENT;
}

#ifdef __KERNEL

void
lnet_destory_rtrbuf(lnet_rtrbuf_t *rb, int npages)
{
        int sz = offsetof(lnet_rtrbuf_t, rb_kiov[npages]);

        while (--npages >= 0)
                __free_page(rb->rb_kiov[npages].kiov_page);
        
        PORTAL_FREE(rb, sz);
}

lnet_rtrbuf_t *
lnet_new_rtrbuf(lnet_rtrbufpool_t *rbp)
{
        int            npages = rbp->rbp_npages;
        int            sz = offsetof(lnet_rtrbuf_t, rb_kiov[npages]);
        struct page   *page;
        lnet_rtrbuf_t *rb;
        int            i;
        
        PORTAL_ALLOC(rb, sz);

        rb->rb_pool = rbp;

        for (i = 0; i < npages; i++) {
                page = alloc_page(GFP_KERNEL); /* HIGH? */
                if (page == NULL) {
                        while (--i >= 0)
                                __free_page(rb->rb_kiov[i].kiov_page);
                        
                        PORTAL_FREE(rb, sz);
                        return NULL;
                }

                rb->rb_kiov[i].kiov_len = PAGE_SIZE;
                rb->rb_kiov[i].kiov_offset = 0;
                rb->rb_kiov[i].kiov_page = page;
        }
        
        return rb;
}

void
lnet_rtrpool_free_bufs(lnet_rtrbufpool_t *rbp) 
{
        int            npages = rbp->rbp_npages;
        int            nbuffers = 0;
        lnet_rtrbuf_t *rb;

        LASSERT (list_empty(&rbp->rbp_msgs));
        LASSERT (rbp->rbp_credits == rbp->rbp_nbuffers);

        while (!list_empty(&rbp->rbp_bufs)) {
                LASSERT (rbp->rbp_credits > 0);
                
                rb = list_entry(rbp->rbp_bufs.next,
                                lnet_rtrbuf_t, rb_list);
                list_del(&rb->rb_list);
                lnet_destory_rtrbuf(rb, npages);
                nbuffers++;
        }

        LASSERT (rbp->rbp_nbuffers == nbuffers);
        LASSERT (rbp->rbp_credits == nbuffers);
        
        rbp->rbp_nbuffers = rbp->rbp_credits = 0;
}

int
lnet_rtrpool_alloc_bufs(lnet_rtrbufpool_t *rbp, int nbufs)
{
        lnet_rtrbuf_t *rb;
        int            i;
        
        for (i = 0; i < nbufs; i++) {
                rb = lnet_new_rtrbuf(rbp);
                
                if (rb == NULL) {
                        CERROR("Failed to allocate %d router bufs of %d pages\n",
                               nbufs, rbp->rbp_npages);
                        return -ENOMEM;
                }
                
                rbp->rbp_nbuffers++;
                rbp->rbp_credits++;
                list_add(&rb->rb_list, &rbp->rbp_bufs);
                
                /* NB if this is live there need to be code to schedule blocked
                 * msgs */
        }

        LASSERT (rbp->rbp_credits == nbufs);
        return 0;
}

void
lnet_rtrpool_init(lnet_rtrbufpool_t *rbp, int npages)
{
        CFS_INIT_LIST_HEAD(&rbp->rbp_msgs);
        CFS_INIT_LIST_HEAD(&rbp->rbp_bufs);

        rbp->rbp_npages = npages;
        rbp->rbp_credits = 0;
        rbp->rbp_mincredits = 0;
}

void
lnet_free_rtrpools(void)
{
        lnet_rtrpool_free_bufs(&the_lnet.ln_rtrpools[0]);
        lnet_rtrpool_free_bufs(&the_lnet.ln_rtrpools[1]);
        lnet_rtrpool_free_bufs(&the_lnet.ln_rtrpools[2]);
}

int
lnet_alloc_rtrpools(void)
{
        int small_pages = 1;
        int large_pages = (PTL_MTU + PAGE_SIZE - 1) / PAGE_SIZE;
        int rc;

        lnet_rtrpool_init(&the_lnet.ln_rtrpools[0], 0);
        lnet_rtrpool_init(&the_lnet.ln_rtrpools[1], small_pages);
        lnet_rtrpool_init(&the_lnet.ln_rtrpools[2], large_pages);

        for (rc = 0; rc < LNET_NRBPOOLS; rc++)
                CDEBUG(D_WARNING, "Pages[%d]: %d\n", rc,
                       the_lnet.ln_rtrpools[rc].rbp_npages);

        the_lnet.ln_routing = forwarding;
        if (!forwarding)
                return 0;
        
        if (tiny_router_buffers <= 0) {
                LCONSOLE_ERROR("tiny_router_buffers=%d invalid when "
                               "routing enabled\n", tiny_router_buffers);
                rc = -EINVAL;
                goto failed;
        }

        rc = lnet_rtrpool_alloc_bufs(&the_lnet.ln_rtrpools[0], 
                                     tiny_router_buffers);
        if (rc != 0)
                goto failed;
        
        if (small_router_buffers <= 0) {
                LCONSOLE_ERROR("small_router_buffers=%d invalid when "
                               "routing enabled\n", small_router_buffers);
                rc = -EINVAL;
                goto failed;
        }

        rc = lnet_rtrpool_alloc_bufs(&the_lnet.ln_rtrpools[1], 
                                     small_router_buffers);
        if (rc != 0)
                goto failed;
        
        if (large_router_buffers <= 0) {
                LCONSOLE_ERROR("large_router_buffers=%d invalid when "
                               "routing enabled\n", large_router_buffers);
                rc = -EINVAL;
                goto failed;
        }

        rc = lnet_rtrpool_alloc_bufs(&the_lnet.ln_rtrpools[2], 
                                     large_router_buffers);
        if (rc != 0)
                goto failed;

        return 0;
        
 failed:
        lnet_free_rtrpools();
        return rc;
}

#else

void
lnet_free_rtrpools (void)
{
}

int
lnet_alloc_rtrpools (void)
{
        /* No userspace routing */
        the_lnet.ln_routing = 0;
        return 0;
}

#endif
