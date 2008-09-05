/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
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

#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>

#if defined(__KERNEL__) && defined(LNET_ROUTER)

static char *forwarding = "";
CFS_MODULE_PARM(forwarding, "s", charp, 0444,
                "Explicitly enable/disable forwarding between networks");

static int tiny_router_buffers = 1024;
CFS_MODULE_PARM(tiny_router_buffers, "i", int, 0444,
                "# of 0 payload messages to buffer in the router");
static int small_router_buffers = 8192;
CFS_MODULE_PARM(small_router_buffers, "i", int, 0444,
                "# of small (1 page) messages to buffer in the router");
static int large_router_buffers = 512;
CFS_MODULE_PARM(large_router_buffers, "i", int, 0444,
                "# of large messages to buffer in the router");

static int auto_down = 1;
CFS_MODULE_PARM(auto_down, "i", int, 0444,
                "Automatically mark peers down on comms error");

static int check_routers_before_use = 0;
CFS_MODULE_PARM(check_routers_before_use, "i", int, 0444,
                "Assume routers are down and ping them before use");

static int dead_router_check_interval = 0;
CFS_MODULE_PARM(dead_router_check_interval, "i", int, 0444,
                "Seconds between dead router health checks (<= 0 to disable)");

static int live_router_check_interval = 0;
CFS_MODULE_PARM(live_router_check_interval, "i", int, 0444,
                "Seconds between live router health checks (<= 0 to disable)");

static int router_ping_timeout = 50;
CFS_MODULE_PARM(router_ping_timeout, "i", int, 0444,
                "Seconds to wait for the reply to a router health query");

int
lnet_peers_start_down(void)
{
        return check_routers_before_use;
}

void
lnet_notify_locked(lnet_peer_t *lp, int notifylnd, int alive, time_t when)
{
        if (when < lp->lp_timestamp) {          /* out of date information */
                CDEBUG(D_NET, "Out of date\n");
                return;
        }

        lp->lp_timestamp = when;                /* update timestamp */
        lp->lp_ping_deadline = 0;               /* disable ping timeout */

        if (lp->lp_alive_count != 0 &&          /* got old news */
            (!lp->lp_alive) == (!alive)) {      /* new date for old news */
                CDEBUG(D_NET, "Old news\n");
                return;
        }

        /* Flag that notification is outstanding */

        lp->lp_alive_count++;
        lp->lp_alive = !(!alive);               /* 1 bit! */
        lp->lp_notify = 1;
        lp->lp_notifylnd |= notifylnd;

        CDEBUG(D_NET, "set %s %d\n", libcfs_nid2str(lp->lp_nid), alive);
}

void
lnet_do_notify (lnet_peer_t *lp)
{
        lnet_ni_t *ni = lp->lp_ni;
        int        alive;
        int        notifylnd;

        LNET_LOCK();

        /* Notify only in 1 thread at any time to ensure ordered notification.
         * NB individual events can be missed; the only guarantee is that you
         * always get the most recent news */

        if (lp->lp_notifying) {
                LNET_UNLOCK();
                return;
        }

        lp->lp_notifying = 1;

        while (lp->lp_notify) {
                alive     = lp->lp_alive;
                notifylnd = lp->lp_notifylnd;

                lp->lp_notifylnd = 0;
                lp->lp_notify    = 0;

                if (notifylnd && ni->ni_lnd->lnd_notify != NULL) {
                        LNET_UNLOCK();

                        /* A new notification could happen now; I'll handle it
                         * when control returns to me */

                        (ni->ni_lnd->lnd_notify)(ni, lp->lp_nid, alive);

                        LNET_LOCK();
                }
        }

        lp->lp_notifying = 0;

        LNET_UNLOCK();
}

int
lnet_notify (lnet_ni_t *ni, lnet_nid_t nid, int alive, time_t when)
{
        lnet_peer_t         *lp = NULL;
        time_t               now = cfs_time_current_sec();

        LASSERT (!in_interrupt ());

        CDEBUG (D_NET, "%s notifying %s: %s\n",
                (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
                libcfs_nid2str(nid),
                alive ? "up" : "down");

        if (ni != NULL &&
            LNET_NIDNET(ni->ni_nid) != LNET_NIDNET(nid)) {
                CWARN ("Ignoring notification of %s %s by %s (different net)\n",
                        libcfs_nid2str(nid), alive ? "birth" : "death",
                        libcfs_nid2str(ni->ni_nid));
                return -EINVAL;
        }

        /* can't do predictions... */
        if (when > now) {
                CWARN ("Ignoring prediction from %s of %s %s "
                       "%ld seconds in the future\n",
                       (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
                       libcfs_nid2str(nid), alive ? "up" : "down",
                       when - now);
                return -EINVAL;
        }

        if (ni != NULL && !alive &&             /* LND telling me she's down */
            !auto_down) {                       /* auto-down disabled */
                CDEBUG(D_NET, "Auto-down disabled\n");
                return 0;
        }

        LNET_LOCK();

        lp = lnet_find_peer_locked(nid);
        if (lp == NULL) {
                /* nid not found */
                LNET_UNLOCK();
                CDEBUG(D_NET, "%s not found\n", libcfs_nid2str(nid));
                return 0;
        }

        lnet_notify_locked(lp, ni == NULL, alive, when);

        LNET_UNLOCK();

        lnet_do_notify(lp);

        LNET_LOCK();

        lnet_peer_decref_locked(lp);

        LNET_UNLOCK();
        return 0;
}
EXPORT_SYMBOL(lnet_notify);

#else

int
lnet_notify (lnet_ni_t *ni, lnet_nid_t nid, int alive, time_t when)
{
        return -EOPNOTSUPP;
}

#endif

static void
lnet_rtr_addref_locked(lnet_peer_t *lp)
{
        LASSERT (lp->lp_refcount > 0);
        LASSERT (lp->lp_rtr_refcount >= 0);

        lp->lp_rtr_refcount++;
        if (lp->lp_rtr_refcount == 1) {
                struct list_head *pos;

                /* a simple insertion sort */
                list_for_each_prev(pos, &the_lnet.ln_routers) {
                        lnet_peer_t *rtr = list_entry(pos, lnet_peer_t, 
                                                      lp_rtr_list);

                        if (rtr->lp_nid < lp->lp_nid)
                                break;
                }

                list_add(&lp->lp_rtr_list, pos);
                /* addref for the_lnet.ln_routers */
                lnet_peer_addref_locked(lp);
                the_lnet.ln_routers_version++;
        }
}

static void
lnet_rtr_decref_locked(lnet_peer_t *lp)
{
        LASSERT (lp->lp_refcount > 0);
        LASSERT (lp->lp_rtr_refcount > 0);

        lp->lp_rtr_refcount--;
        if (lp->lp_rtr_refcount == 0) {
                list_del(&lp->lp_rtr_list);
                /* decref for the_lnet.ln_routers */
                lnet_peer_decref_locked(lp);
                the_lnet.ln_routers_version++;
        }
}

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
lnet_add_route (__u32 net, unsigned int hops, lnet_nid_t gateway)
{
        struct list_head     zombies;
        struct list_head    *e;
        lnet_remotenet_t    *rnet;
        lnet_remotenet_t    *rnet2;
        lnet_route_t        *route;
        lnet_route_t        *route2;
        lnet_ni_t           *ni;
        int                  add_route;
        int                  rc;

        CDEBUG(D_NET, "Add route: net %s hops %u gw %s\n",
               libcfs_net2str(net), hops, libcfs_nid2str(gateway));

        if (gateway == LNET_NID_ANY ||
            LNET_NETTYP(LNET_NIDNET(gateway)) == LOLND ||
            net == LNET_NIDNET(LNET_NID_ANY) ||
            LNET_NETTYP(net) == LOLND ||
            LNET_NIDNET(gateway) == net ||
            hops < 1 || hops > 255)
                return (-EINVAL);

        if (lnet_islocalnet(net))               /* it's a local network */
                return 0;                       /* ignore the route entry */

        /* Assume net, route, all new */
        LIBCFS_ALLOC(route, sizeof(*route));
        LIBCFS_ALLOC(rnet, sizeof(*rnet));
        if (route == NULL || rnet == NULL) {
                CERROR("Out of memory creating route %s %d %s\n",
                       libcfs_net2str(net), hops, libcfs_nid2str(gateway));
                if (route != NULL)
                        LIBCFS_FREE(route, sizeof(*route));
                if (rnet != NULL)
                        LIBCFS_FREE(rnet, sizeof(*rnet));
                return -ENOMEM;
        }

        CFS_INIT_LIST_HEAD(&rnet->lrn_routes);
        rnet->lrn_net = net;
        rnet->lrn_hops = hops;

        LNET_LOCK();

        rc = lnet_nid2peer_locked(&route->lr_gateway, gateway);
        if (rc != 0) {
                LNET_UNLOCK();

                LIBCFS_FREE(route, sizeof(*route));
                LIBCFS_FREE(rnet, sizeof(*rnet));

                if (rc == -EHOSTUNREACH)        /* gateway is not on a local net */
                        return 0;               /* ignore the route entry */

                CERROR("Error %d creating route %s %d %s\n", rc,
                       libcfs_net2str(net), hops, libcfs_nid2str(gateway));
                return rc;
        }

        LASSERT (!the_lnet.ln_shutdown);
        CFS_INIT_LIST_HEAD(&zombies);

        rnet2 = lnet_find_net_locked(net);
        if (rnet2 == NULL) {
                /* new network */
                list_add_tail(&rnet->lrn_list, &the_lnet.ln_remote_nets);
                rnet2 = rnet;
        }

        if (hops > rnet2->lrn_hops) {
                /* New route is longer; ignore it */
                add_route = 0;
        } else if (hops < rnet2->lrn_hops) {
                /* new route supercedes all currently known routes to this
                 * net */
                list_add(&zombies, &rnet2->lrn_routes);
                list_del_init(&rnet2->lrn_routes);
                add_route = 1;
        } else {
                add_route = 1;
                /* New route has the same hopcount as existing routes; search
                 * for a duplicate route (it's a NOOP if it is) */
                list_for_each (e, &rnet2->lrn_routes) {
                        route2 = list_entry(e, lnet_route_t, lr_list);

                        if (route2->lr_gateway == route->lr_gateway) {
                                add_route = 0;
                                break;
                        }

                        /* our loopups must be true */
                        LASSERT (route2->lr_gateway->lp_nid != gateway);
                }
        }

        if (add_route) {
                ni = route->lr_gateway->lp_ni;
                lnet_ni_addref_locked(ni);

                LASSERT (rc == 0);
                list_add_tail(&route->lr_list, &rnet2->lrn_routes);
                the_lnet.ln_remote_nets_version++;

                lnet_rtr_addref_locked(route->lr_gateway);

                LNET_UNLOCK();

                /* XXX Assume alive */
                if (ni->ni_lnd->lnd_notify != NULL)
                        (ni->ni_lnd->lnd_notify)(ni, gateway, 1);

                lnet_ni_decref(ni);
        } else {
                lnet_peer_decref_locked(route->lr_gateway);
                LNET_UNLOCK();
                LIBCFS_FREE(route, sizeof(*route));
        }

        if (rnet != rnet2)
                LIBCFS_FREE(rnet, sizeof(*rnet));

        while (!list_empty(&zombies)) {
                route = list_entry(zombies.next, lnet_route_t, lr_list);
                list_del(&route->lr_list);

                LNET_LOCK();
                lnet_rtr_decref_locked(route->lr_gateway);
                lnet_peer_decref_locked(route->lr_gateway);
                LNET_UNLOCK();
                LIBCFS_FREE(route, sizeof(*route));
        }

        return rc;
}

int
lnet_check_routes (void)
{
        lnet_remotenet_t    *rnet;
        lnet_route_t        *route;
        lnet_route_t        *route2;
        struct list_head    *e1;
        struct list_head    *e2;

        LNET_LOCK();

        list_for_each (e1, &the_lnet.ln_remote_nets) {
                rnet = list_entry(e1, lnet_remotenet_t, lrn_list);

                route2 = NULL;
                list_for_each (e2, &rnet->lrn_routes) {
                        route = list_entry(e2, lnet_route_t, lr_list);

                        if (route2 == NULL)
                                route2 = route;
                        else if (route->lr_gateway->lp_ni !=
                                 route2->lr_gateway->lp_ni) {
                                LNET_UNLOCK();

                                CERROR("Routes to %s via %s and %s not supported\n",
                                       libcfs_net2str(rnet->lrn_net),
                                       libcfs_nid2str(route->lr_gateway->lp_nid),
                                       libcfs_nid2str(route2->lr_gateway->lp_nid));
                                return -EINVAL;
                        }
                }
        }

        LNET_UNLOCK();
        return 0;
}

int
lnet_del_route (__u32 net, lnet_nid_t gw_nid)
{
        lnet_remotenet_t    *rnet;
        lnet_route_t        *route;
        struct list_head    *e1;
        struct list_head    *e2;
        int                  rc = -ENOENT;

        CDEBUG(D_NET, "Del route: net %s : gw %s\n",
               libcfs_net2str(net), libcfs_nid2str(gw_nid));

        /* NB Caller may specify either all routes via the given gateway
         * or a specific route entry actual NIDs) */

 again:
        LNET_LOCK();

        list_for_each (e1, &the_lnet.ln_remote_nets) {
                rnet = list_entry(e1, lnet_remotenet_t, lrn_list);

                if (!(net == LNET_NIDNET(LNET_NID_ANY) ||
                      net == rnet->lrn_net))
                        continue;

                list_for_each (e2, &rnet->lrn_routes) {
                        route = list_entry(e2, lnet_route_t, lr_list);

                        if (!(gw_nid == LNET_NID_ANY ||
                              gw_nid == route->lr_gateway->lp_nid))
                                continue;

                        list_del(&route->lr_list);
                        the_lnet.ln_remote_nets_version++;

                        if (list_empty(&rnet->lrn_routes))
                                list_del(&rnet->lrn_list);
                        else
                                rnet = NULL;

                        lnet_rtr_decref_locked(route->lr_gateway);
                        lnet_peer_decref_locked(route->lr_gateway);
                        LNET_UNLOCK();

                        LIBCFS_FREE(route, sizeof (*route));

                        if (rnet != NULL)
                                LIBCFS_FREE(rnet, sizeof(*rnet));

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
        lnet_del_route(LNET_NIDNET(LNET_NID_ANY), LNET_NID_ANY);
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

#if defined(__KERNEL__) && defined(LNET_ROUTER)
static void
lnet_router_checker_event (lnet_event_t *event)
{
        /* CAVEAT EMPTOR: I'm called with LNET_LOCKed and I'm not allowed to
         * drop it (that's how come I see _every_ event, even ones that would
         * overflow my EQ) */
        lnet_peer_t   *lp;
        lnet_nid_t     nid;

        if (event->unlinked) {
                /* The router checker thread has unlinked the rc_md
                 * and exited. */
                LASSERT (the_lnet.ln_rc_state == LNET_RC_STATE_UNLINKING);
                the_lnet.ln_rc_state = LNET_RC_STATE_UNLINKED;
                mutex_up(&the_lnet.ln_rc_signal);
                return;
        }

        LASSERT (event->type == LNET_EVENT_SEND ||
                 event->type == LNET_EVENT_REPLY);

        nid = (event->type == LNET_EVENT_SEND) ?
              event->target.nid : event->initiator.nid;

        lp = lnet_find_peer_locked(nid);
        if (lp == NULL) {
                /* router may have been removed */
                CDEBUG(D_NET, "Router %s not found\n", libcfs_nid2str(nid));
                return;
        }

        if (event->type == LNET_EVENT_SEND)     /* re-enable another ping */
                lp->lp_ping_notsent = 0;

        if (lnet_isrouter(lp) &&                /* ignore if no longer a router */
            (event->status != 0 ||
             event->type == LNET_EVENT_REPLY)) {

                /* A successful REPLY means the router is up.  If _any_ comms
                 * to the router fail I assume it's down (this will happen if
                 * we ping alive routers to try to detect router death before
                 * apps get burned). */

                lnet_notify_locked(lp, 1, (event->status == 0),
                                   cfs_time_current_sec());

                /* The router checker will wake up very shortly and do the
                 * actual notification.  
                 * XXX If 'lp' stops being a router before then, it will still
                 * have the notification pending!!! */
        }

        /* This decref will NOT drop LNET_LOCK (it had to have 1 ref when it
         * was in the peer table and I've not dropped the lock, so no-one else
         * can have reduced the refcount) */
        LASSERT(lp->lp_refcount > 1);

        lnet_peer_decref_locked(lp);
}

static int
lnet_router_checker(void *arg)
{
        static lnet_ping_info_t   pinginfo;

        int                  rc;
        lnet_handle_md_t     mdh;
        lnet_peer_t         *rtr;
        struct list_head    *entry;
        time_t               now;
        lnet_process_id_t    rtr_id;
        int                  secs;

        cfs_daemonize("router_checker");
        cfs_block_allsigs();

        rtr_id.pid = LUSTRE_SRV_LNET_PID;

        LASSERT (the_lnet.ln_rc_state == LNET_RC_STATE_SHUTDOWN);

        rc = LNetMDBind((lnet_md_t){.start     = &pinginfo,
                                    .length    = sizeof(pinginfo),
                                    .threshold = LNET_MD_THRESH_INF,
                                    .options   = LNET_MD_TRUNCATE,
                                    .eq_handle = the_lnet.ln_rc_eqh},
                        LNET_UNLINK,
                        &mdh);

        if (rc < 0) {
                CERROR("Can't bind MD: %d\n", rc);
                the_lnet.ln_rc_state = rc;
                mutex_up(&the_lnet.ln_rc_signal);
                return rc;
        }

        LASSERT (rc == 0);

        the_lnet.ln_rc_state = LNET_RC_STATE_RUNNING;
        mutex_up(&the_lnet.ln_rc_signal);       /* let my parent go */

        while (the_lnet.ln_rc_state == LNET_RC_STATE_RUNNING) {
                __u64 version;

                LNET_LOCK();
rescan:
                version = the_lnet.ln_routers_version;

                list_for_each (entry, &the_lnet.ln_routers) {
                        rtr = list_entry(entry, lnet_peer_t, lp_rtr_list);

                        lnet_peer_addref_locked(rtr);

                        now = cfs_time_current_sec();

                        if (rtr->lp_ping_deadline != 0 && /* ping timed out? */
                            now > rtr->lp_ping_deadline)
                                lnet_notify_locked(rtr, 1, 0, now);

                        LNET_UNLOCK();

                        /* Run any outstanding notificiations */
                        lnet_do_notify(rtr);

                        if (rtr->lp_alive) {
                                secs = live_router_check_interval;
                        } else {
                                secs = dead_router_check_interval;
                        }
                        if (secs <= 0)
                                secs = 0;

                        if (secs != 0 &&
                            !rtr->lp_ping_notsent &&
                            now > rtr->lp_ping_timestamp + secs) {
                                CDEBUG(D_NET, "Check: %s\n",
                                       libcfs_nid2str(rtr->lp_nid));

                                LNET_LOCK();
                                rtr_id.nid = rtr->lp_nid;
                                rtr->lp_ping_notsent = 1;
                                rtr->lp_ping_timestamp = now;

                                if (rtr->lp_ping_deadline == 0)
                                        rtr->lp_ping_deadline = 
                                                now + router_ping_timeout;

                                LNET_UNLOCK();

                                LNetGet(LNET_NID_ANY, mdh, rtr_id,
                                        LNET_RESERVED_PORTAL,
                                        LNET_PROTO_PING_MATCHBITS, 0);
                        }

                        LNET_LOCK();
                        lnet_peer_decref_locked(rtr);

                        if (version != the_lnet.ln_routers_version) {
                                /* the routers list has changed */
                                goto rescan;
                        }
                }

                LNET_UNLOCK();

                /* Call cfs_pause() here always adds 1 to load average 
                 * because kernel counts # active tasks as nr_running 
                 * + nr_uninterruptible. */
                set_current_state(CFS_TASK_INTERRUPTIBLE);
                cfs_schedule_timeout(CFS_TASK_INTERRUPTIBLE,
                                     cfs_time_seconds(1));
        }

        LASSERT (the_lnet.ln_rc_state == LNET_RC_STATE_STOPTHREAD);
        the_lnet.ln_rc_state = LNET_RC_STATE_UNLINKING;

        rc = LNetMDUnlink(mdh);
        LASSERT (rc == 0);

        /* The unlink event callback will signal final completion */
        return 0;
}


void
lnet_wait_known_routerstate(void)
{
        lnet_peer_t         *rtr;
        struct list_head    *entry;
        int                  all_known;

        for (;;) {
                LNET_LOCK();

                all_known = 1;
                list_for_each (entry, &the_lnet.ln_routers) {
                        rtr = list_entry(entry, lnet_peer_t, lp_rtr_list);

                        if (rtr->lp_alive_count == 0) {
                                all_known = 0;
                                break;
                        }
                }

                LNET_UNLOCK();

                if (all_known)
                        return;

                cfs_pause(cfs_time_seconds(1));
        }
}

void
lnet_router_checker_stop(void)
{
        int       rc;

        LASSERT (the_lnet.ln_rc_state == LNET_RC_STATE_RUNNING ||
                 the_lnet.ln_rc_state == LNET_RC_STATE_SHUTDOWN);

        if (the_lnet.ln_rc_state == LNET_RC_STATE_SHUTDOWN)
                return;

        the_lnet.ln_rc_state = LNET_RC_STATE_STOPTHREAD;
        /* block until event callback signals exit */
        mutex_down(&the_lnet.ln_rc_signal);

        LASSERT (the_lnet.ln_rc_state == LNET_RC_STATE_UNLINKED);

        rc = LNetEQFree(the_lnet.ln_rc_eqh);
        LASSERT (rc == 0);

        the_lnet.ln_rc_state = LNET_RC_STATE_SHUTDOWN;
}

int
lnet_router_checker_start(void)
{
        int  rc;

        LASSERT (the_lnet.ln_rc_state == LNET_RC_STATE_SHUTDOWN);

        if (check_routers_before_use &&
            dead_router_check_interval <= 0) {
                LCONSOLE_ERROR_MSG(0x10a, "'dead_router_check_interval' must be"
                                   " set if 'check_routers_before_use' is set"
                                   "\n");
                return -EINVAL;
        }

        if (live_router_check_interval <= 0 &&
            dead_router_check_interval <= 0)
                return 0;

        init_mutex_locked(&the_lnet.ln_rc_signal);

        /* EQ size doesn't matter; the callback is guaranteed to get every
         * event */
        rc = LNetEQAlloc(1, lnet_router_checker_event,
                         &the_lnet.ln_rc_eqh);
        if (rc != 0) {
                CERROR("Can't allocate EQ: %d\n", rc);
                return -ENOMEM;
        }

        rc = (int)cfs_kernel_thread(lnet_router_checker, NULL, 0);
        if (rc < 0) {
                CERROR("Can't start router checker thread: %d\n", rc);
                goto failed;
        }

        mutex_down(&the_lnet.ln_rc_signal);     /* wait for checker to startup */

        rc = the_lnet.ln_rc_state;
        if (rc < 0) {
                the_lnet.ln_rc_state = LNET_RC_STATE_SHUTDOWN;
                goto failed;
        }

        LASSERT (the_lnet.ln_rc_state == LNET_RC_STATE_RUNNING);

        if (check_routers_before_use) {
                /* Note that a helpful side-effect of pinging all known routers
                 * at startup is that it makes them drop stale connections they
                 * may have to a previous instance of me. */
                lnet_wait_known_routerstate();
        }

        return 0;

 failed:
        rc = LNetEQFree(the_lnet.ln_rc_eqh);
        LASSERT (rc == 0);
        return rc;
}

void
lnet_destroy_rtrbuf(lnet_rtrbuf_t *rb, int npages)
{
        int sz = offsetof(lnet_rtrbuf_t, rb_kiov[npages]);

        while (--npages >= 0)
                cfs_free_page(rb->rb_kiov[npages].kiov_page);

        LIBCFS_FREE(rb, sz);
}

lnet_rtrbuf_t *
lnet_new_rtrbuf(lnet_rtrbufpool_t *rbp)
{
        int            npages = rbp->rbp_npages;
        int            sz = offsetof(lnet_rtrbuf_t, rb_kiov[npages]);
        struct page   *page;
        lnet_rtrbuf_t *rb;
        int            i;

        LIBCFS_ALLOC(rb, sz);
        if (rb == NULL)
                return NULL;

        rb->rb_pool = rbp;

        for (i = 0; i < npages; i++) {
                page = cfs_alloc_page(CFS_ALLOC_ZERO | CFS_ALLOC_STD);
                if (page == NULL) {
                        while (--i >= 0)
                                cfs_free_page(rb->rb_kiov[i].kiov_page);

                        LIBCFS_FREE(rb, sz);
                        return NULL;
                }

                rb->rb_kiov[i].kiov_len = CFS_PAGE_SIZE;
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
                lnet_destroy_rtrbuf(rb, npages);
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

        if (rbp->rbp_nbuffers != 0) {
                LASSERT (rbp->rbp_nbuffers == nbufs);
                return 0;
        }

        for (i = 0; i < nbufs; i++) {
                rb = lnet_new_rtrbuf(rbp);

                if (rb == NULL) {
                        CERROR("Failed to allocate %d router bufs of %d pages\n",
                               nbufs, rbp->rbp_npages);
                        return -ENOMEM;
                }

                rbp->rbp_nbuffers++;
                rbp->rbp_credits++;
                rbp->rbp_mincredits++;
                list_add(&rb->rb_list, &rbp->rbp_bufs);

                /* No allocation "under fire" */
                /* Otherwise we'd need code to schedule blocked msgs etc */
                LASSERT (!the_lnet.ln_routing);
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

void
lnet_init_rtrpools(void)
{
        int small_pages = 1;
        int large_pages = (LNET_MTU + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;

        lnet_rtrpool_init(&the_lnet.ln_rtrpools[0], 0);
        lnet_rtrpool_init(&the_lnet.ln_rtrpools[1], small_pages);
        lnet_rtrpool_init(&the_lnet.ln_rtrpools[2], large_pages);
}


int
lnet_alloc_rtrpools(int im_a_router)
{
        int       rc;

        if (!strcmp(forwarding, "")) {
                /* not set either way */
                if (!im_a_router)
                        return 0;
        } else if (!strcmp(forwarding, "disabled")) {
                /* explicitly disabled */
                return 0;
        } else if (!strcmp(forwarding, "enabled")) {
                /* explicitly enabled */
        } else {
                LCONSOLE_ERROR_MSG(0x10b, "'forwarding' not set to either "
                                   "'enabled' or 'disabled'\n");
                return -EINVAL;
        }

        if (tiny_router_buffers <= 0) {
                LCONSOLE_ERROR_MSG(0x10c, "tiny_router_buffers=%d invalid when "
                                   "routing enabled\n", tiny_router_buffers);
                rc = -EINVAL;
                goto failed;
        }

        rc = lnet_rtrpool_alloc_bufs(&the_lnet.ln_rtrpools[0],
                                     tiny_router_buffers);
        if (rc != 0)
                goto failed;

        if (small_router_buffers <= 0) {
                LCONSOLE_ERROR_MSG(0x10d, "small_router_buffers=%d invalid when"
                                   " routing enabled\n", small_router_buffers);
                rc = -EINVAL;
                goto failed;
        }

        rc = lnet_rtrpool_alloc_bufs(&the_lnet.ln_rtrpools[1],
                                     small_router_buffers);
        if (rc != 0)
                goto failed;

        if (large_router_buffers <= 0) {
                LCONSOLE_ERROR_MSG(0x10e, "large_router_buffers=%d invalid when"
                                   " routing enabled\n", large_router_buffers);
                rc = -EINVAL;
                goto failed;
        }

        rc = lnet_rtrpool_alloc_bufs(&the_lnet.ln_rtrpools[2],
                                     large_router_buffers);
        if (rc != 0)
                goto failed;

        LNET_LOCK();
        the_lnet.ln_routing = 1;
        LNET_UNLOCK();

        return 0;

 failed:
        lnet_free_rtrpools();
        return rc;
}

#else

int
lnet_peers_start_down(void)
{
        return 0;
}

void
lnet_router_checker_stop(void)
{
        return;
}

int
lnet_router_checker_start(void)
{
        return 0;
}

void
lnet_free_rtrpools (void)
{
}

void
lnet_init_rtrpools (void)
{
}

int
lnet_alloc_rtrpools (int im_a_arouter)
{
        return 0;
}

#endif
