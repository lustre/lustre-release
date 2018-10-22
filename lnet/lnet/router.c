/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 *   This file is part of Lustre, https://wiki.whamcloud.com/
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

#include <linux/random.h>
#include <lnet/lib-lnet.h>

#define LNET_NRB_TINY_MIN	512	/* min value for each CPT */
#define LNET_NRB_TINY		(LNET_NRB_TINY_MIN * 4)
#define LNET_NRB_SMALL_MIN	4096	/* min value for each CPT */
#define LNET_NRB_SMALL		(LNET_NRB_SMALL_MIN * 4)
#define LNET_NRB_SMALL_PAGES	1
#define LNET_NRB_LARGE_MIN	256	/* min value for each CPT */
#define LNET_NRB_LARGE		(LNET_NRB_LARGE_MIN * 4)
#define LNET_NRB_LARGE_PAGES	((LNET_MTU + PAGE_SIZE - 1) >> \
				  PAGE_SHIFT)

static char *forwarding = "";
module_param(forwarding, charp, 0444);
MODULE_PARM_DESC(forwarding, "Explicitly enable/disable forwarding between networks");

static int tiny_router_buffers;
module_param(tiny_router_buffers, int, 0444);
MODULE_PARM_DESC(tiny_router_buffers, "# of 0 payload messages to buffer in the router");
static int small_router_buffers;
module_param(small_router_buffers, int, 0444);
MODULE_PARM_DESC(small_router_buffers, "# of small (1 page) messages to buffer in the router");
static int large_router_buffers;
module_param(large_router_buffers, int, 0444);
MODULE_PARM_DESC(large_router_buffers, "# of large messages to buffer in the router");
static int peer_buffer_credits;
module_param(peer_buffer_credits, int, 0444);
MODULE_PARM_DESC(peer_buffer_credits, "# router buffer credits per peer");

static int auto_down = 1;
module_param(auto_down, int, 0444);
MODULE_PARM_DESC(auto_down, "Automatically mark peers down on comms error");

int
lnet_peer_buffer_credits(struct lnet_net *net)
{
	/* NI option overrides LNet default */
	if (net->net_tunables.lct_peer_rtr_credits > 0)
		return net->net_tunables.lct_peer_rtr_credits;
	if (peer_buffer_credits > 0)
		return peer_buffer_credits;

	/* As an approximation, allow this peer the same number of router
	 * buffers as it is allowed outstanding sends */
	return net->net_tunables.lct_peer_tx_credits;
}

static int check_routers_before_use;
module_param(check_routers_before_use, int, 0444);
MODULE_PARM_DESC(check_routers_before_use, "Assume routers are down and ping them before use");

int avoid_asym_router_failure = 1;
module_param(avoid_asym_router_failure, int, 0644);
MODULE_PARM_DESC(avoid_asym_router_failure, "Avoid asymmetrical router failures (0 to disable)");

static int dead_router_check_interval = 60;
module_param(dead_router_check_interval, int, 0644);
MODULE_PARM_DESC(dead_router_check_interval, "Seconds between dead router health checks (<= 0 to disable)");

static int live_router_check_interval = 60;
module_param(live_router_check_interval, int, 0644);
MODULE_PARM_DESC(live_router_check_interval, "Seconds between live router health checks (<= 0 to disable)");

static int router_ping_timeout = 50;
module_param(router_ping_timeout, int, 0644);
MODULE_PARM_DESC(router_ping_timeout, "Seconds to wait for the reply to a router health query");

/*
 * A value between 0 and 100. 0 meaning that even if router's interfaces
 * have the worse health still consider the gateway usable.
 * 100 means that at least one interface on the route's remote net is 100%
 * healthy to consider the route alive.
 * The default is set to 100 to ensure we maintain the original behavior.
 */
unsigned int router_sensitivity_percentage = 100;
static int rtr_sensitivity_set(const char *val, cfs_kernel_param_arg_t *kp);
static struct kernel_param_ops param_ops_rtr_sensitivity = {
	.set = rtr_sensitivity_set,
	.get = param_get_int,
};
#define param_check_rtr_sensitivity(name, p) \
		__param_check(name, p, int)
#ifdef HAVE_KERNEL_PARAM_OPS
module_param(router_sensitivity_percentage, rtr_sensitivity, S_IRUGO|S_IWUSR);
#else
module_param_call(router_sensitivity_percentage, rtr_sensitivity_set, param_get_int,
		  &router_sensitivity_percentage, S_IRUGO|S_IWUSR);
#endif
MODULE_PARM_DESC(router_sensitivity_percentage,
		"How healthy a gateway should be to be used in percent");

static int
rtr_sensitivity_set(const char *val, cfs_kernel_param_arg_t *kp)
{
	int rc;
	unsigned *sen = (unsigned *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'router_sensitivity_percentage'\n");
		return rc;
	}

	if (value < 0 || value > 100) {
		CERROR("Invalid value: %lu for 'router_sensitivity_percentage'\n", value);
		return -EINVAL;
	}

	/*
	 * The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	*sen = value;

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

int
lnet_peers_start_down(void)
{
	return check_routers_before_use;
}

/*
 * A net is alive if at least one gateway NI on the network is alive.
 */
static bool
lnet_is_gateway_net_alive(struct lnet_peer_net *lpn)
{
	struct lnet_peer_ni *lpni;

	list_for_each_entry(lpni, &lpn->lpn_peer_nis, lpni_peer_nis) {
		if (lnet_is_peer_ni_alive(lpni))
			return true;
	}

	return false;
}

/*
 * a gateway is alive only if all its nets are alive
 * called with cpt lock held
 */
bool lnet_is_gateway_alive(struct lnet_peer *gw)
{
	struct lnet_peer_net *lpn;

	list_for_each_entry(lpn, &gw->lp_peer_nets, lpn_peer_nets) {
		if (!lnet_is_gateway_net_alive(lpn))
			return false;
	}

	return true;
}

/*
 * lnet_is_route_alive() needs to be called with cpt lock held
 * A route is alive if the gateway can route between the local network and
 * the remote network of the route.
 * This means at least one NI is alive on each of the local and remote
 * networks of the gateway.
 */
bool lnet_is_route_alive(struct lnet_route *route)
{
	struct lnet_peer *gw = route->lr_gateway;
	struct lnet_peer_net *llpn;
	struct lnet_peer_net *rlpn;
	bool route_alive;

	/*
	 * check the gateway's interfaces on the route rnet to make sure
	 * that the gateway is viable.
	 */
	llpn = lnet_peer_get_net_locked(gw, route->lr_lnet);
	if (!llpn)
		return false;

	route_alive = lnet_is_gateway_net_alive(llpn);

	if (avoid_asym_router_failure) {
		rlpn = lnet_peer_get_net_locked(gw, route->lr_net);
		if (!rlpn)
			return false;
		route_alive = route_alive &&
			      lnet_is_gateway_net_alive(rlpn);
	}

	if (!route_alive)
		return route_alive;

	spin_lock(&gw->lp_lock);
	if (!(gw->lp_state & LNET_PEER_ROUTER_ENABLED)) {
		if (gw->lp_rtr_refcount > 0)
			CERROR("peer %s is being used as a gateway but routing feature is not turned on\n",
			       libcfs_nid2str(gw->lp_primary_nid));
		route_alive = false;
	}
	spin_unlock(&gw->lp_lock);

	return route_alive;
}

static void
lnet_rtr_addref_locked(struct lnet_peer *lp)
{
	LASSERT(lp->lp_rtr_refcount >= 0);

	/* lnet_net_lock must be exclusively locked */
	lp->lp_rtr_refcount++;
	if (lp->lp_rtr_refcount == 1) {
		list_add_tail(&lp->lp_rtr_list, &the_lnet.ln_routers);
		/* addref for the_lnet.ln_routers */
		lnet_peer_addref_locked(lp);
		the_lnet.ln_routers_version++;
	}
}

static void
lnet_rtr_decref_locked(struct lnet_peer *lp)
{
	LASSERT(atomic_read(&lp->lp_refcount) > 0);
	LASSERT(lp->lp_rtr_refcount > 0);

	/* lnet_net_lock must be exclusively locked */
	lp->lp_rtr_refcount--;
	if (lp->lp_rtr_refcount == 0) {
		LASSERT(list_empty(&lp->lp_routes));

		list_del(&lp->lp_rtr_list);
		/* decref for the_lnet.ln_routers */
		lnet_peer_decref_locked(lp);
		the_lnet.ln_routers_version++;
	}
}

struct lnet_remotenet *
lnet_find_rnet_locked(__u32 net)
{
	struct lnet_remotenet *rnet;
	struct list_head *tmp;
	struct list_head *rn_list;

	LASSERT(the_lnet.ln_state == LNET_STATE_RUNNING);

	rn_list = lnet_net2rnethash(net);
	list_for_each(tmp, rn_list) {
		rnet = list_entry(tmp, struct lnet_remotenet, lrn_list);

		if (rnet->lrn_net == net)
			return rnet;
	}
	return NULL;
}

static void lnet_shuffle_seed(void)
{
	static int seeded;
	struct lnet_ni *ni = NULL;

	if (seeded)
		return;

	/* Nodes with small feet have little entropy
	 * the NID for this node gives the most entropy in the low bits */
	while ((ni = lnet_get_next_ni_locked(NULL, ni)))
		add_device_randomness(&ni->ni_nid, sizeof(ni->ni_nid));

	seeded = 1;
	return;
}

/* NB expects LNET_LOCK held */
static void
lnet_add_route_to_rnet(struct lnet_remotenet *rnet, struct lnet_route *route)
{
	unsigned int len = 0;
	unsigned int offset = 0;
	struct list_head *e;

	lnet_shuffle_seed();

	list_for_each(e, &rnet->lrn_routes)
		len++;

	/*
	 * Randomly adding routes to the list is done to ensure that when
	 * different nodes are using the same list of routers, they end up
	 * preferring different routers.
	 */
	offset = cfs_rand() % (len + 1);
	list_for_each(e, &rnet->lrn_routes) {
		if (offset == 0)
			break;
		offset--;
	}
	list_add(&route->lr_list, e);
	/*
	 * force a router check on the gateway to make sure the route is
	 * alive
	 */
	route->lr_gateway->lp_rtrcheck_timestamp = 0;

	the_lnet.ln_remote_nets_version++;

	/* add the route on the gateway list */
	list_add(&route->lr_gwlist, &route->lr_gateway->lp_routes);

	/* take a router reference count on the gateway */
	lnet_rtr_addref_locked(route->lr_gateway);
}

int
lnet_add_route(__u32 net, __u32 hops, lnet_nid_t gateway,
	       unsigned int priority)
{
	struct list_head *route_entry;
	struct lnet_remotenet *rnet;
	struct lnet_remotenet *rnet2;
	struct lnet_route *route;
	struct lnet_peer_ni *lpni;
	struct lnet_peer *gw;
	int add_route;
	int rc;

	CDEBUG(D_NET, "Add route: remote net %s hops %d priority %u gw %s\n",
	       libcfs_net2str(net), hops, priority, libcfs_nid2str(gateway));

	if (gateway == LNET_NID_ANY ||
	    LNET_NETTYP(LNET_NIDNET(gateway)) == LOLND ||
	    net == LNET_NIDNET(LNET_NID_ANY) ||
	    LNET_NETTYP(net) == LOLND ||
	    LNET_NIDNET(gateway) == net ||
	    (hops != LNET_UNDEFINED_HOPS && (hops < 1 || hops > 255)))
		return -EINVAL;

	/* it's a local network */
	if (lnet_islocalnet(net))
		return -EEXIST;

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

	INIT_LIST_HEAD(&rnet->lrn_routes);
	rnet->lrn_net = net;
	/* store the local and remote net that the route represents */
	route->lr_lnet = LNET_NIDNET(gateway);
	route->lr_net = net;
	route->lr_priority = priority;
	route->lr_hops = hops;

	lnet_net_lock(LNET_LOCK_EX);

	/*
	 * lnet_nid2peerni_ex() grabs a ref on the lpni. We will need to
	 * lose that once we're done
	 */
	lpni = lnet_nid2peerni_ex(gateway, LNET_LOCK_EX);
	if (IS_ERR(lpni)) {
		lnet_net_unlock(LNET_LOCK_EX);

		LIBCFS_FREE(route, sizeof(*route));
		LIBCFS_FREE(rnet, sizeof(*rnet));

		rc = PTR_ERR(lpni);
		CERROR("Error %d creating route %s %d %s\n", rc,
			libcfs_net2str(net), hops,
			libcfs_nid2str(gateway));
		return rc;
	}

	LASSERT(lpni->lpni_peer_net && lpni->lpni_peer_net->lpn_peer);
	gw = lpni->lpni_peer_net->lpn_peer;

	route->lr_gateway = gw;

	rnet2 = lnet_find_rnet_locked(net);
	if (rnet2 == NULL) {
		/* new network */
		list_add_tail(&rnet->lrn_list, lnet_net2rnethash(net));
		rnet2 = rnet;
	}

	/* Search for a duplicate route (it's a NOOP if it is) */
	add_route = 1;
	list_for_each(route_entry, &rnet2->lrn_routes) {
		struct lnet_route *route2;

		route2 = list_entry(route_entry, struct lnet_route, lr_list);
		if (route2->lr_gateway == route->lr_gateway) {
			add_route = 0;
			break;
		}

		/* our lookups must be true */
		LASSERT(route2->lr_gateway->lp_primary_nid != gateway);
	}

	/*
	 * It is possible to add multiple routes through the same peer,
	 * but it'll be using a different NID of that peer. When the
	 * gateway is discovered, discovery will consolidate the different
	 * peers into one peer. In this case the discovery code will have
	 * to move the routes from the peer that's being deleted to the
	 * consolidated peer lp_routes list
	 */
	if (add_route)
		lnet_add_route_to_rnet(rnet2, route);

	/*
	 * get rid of the reference on the lpni.
	 */
	lnet_peer_ni_decref_locked(lpni);
	lnet_net_unlock(LNET_LOCK_EX);

	rc = 0;

	if (!add_route) {
		rc = -EEXIST;
		LIBCFS_FREE(route, sizeof(*route));
	}

	if (rnet != rnet2)
		LIBCFS_FREE(rnet, sizeof(*rnet));

	/* kick start the monitor thread to handle the added route */
	wake_up(&the_lnet.ln_mt_waitq);

	return rc;
}

static void
lnet_del_route_from_rnet(lnet_nid_t gw_nid, struct list_head *route_list,
			 struct list_head *zombies)
{
	struct lnet_peer *gateway;
	struct lnet_route *route;
	struct lnet_route *tmp;

	list_for_each_entry_safe(route, tmp, route_list, lr_list) {
		gateway = route->lr_gateway;
		if (gw_nid != LNET_NID_ANY &&
		    gw_nid != gateway->lp_primary_nid)
			continue;

		/*
		 * move to zombie to delete outside the lock
		 * Note that this function is called with the
		 * ln_api_mutex held as well as the exclusive net
		 * lock. Adding to the remote net list happens
		 * under the same conditions. Same goes for the
		 * gateway router list
		 */
		list_move(&route->lr_list, zombies);
		the_lnet.ln_remote_nets_version++;

		list_del(&route->lr_gwlist);
		lnet_rtr_decref_locked(gateway);
	}
}

int
lnet_del_route(__u32 net, lnet_nid_t gw_nid)
{
	struct list_head rnet_zombies;
	struct lnet_remotenet *rnet;
	struct lnet_remotenet *tmp;
	struct list_head *rn_list;
	struct lnet_peer_ni *lpni;
	struct lnet_route *route;
	struct list_head zombies;
	struct lnet_peer *lp;
	int i = 0;

	INIT_LIST_HEAD(&rnet_zombies);
	INIT_LIST_HEAD(&zombies);

	CDEBUG(D_NET, "Del route: net %s : gw %s\n",
	       libcfs_net2str(net), libcfs_nid2str(gw_nid));

	/* NB Caller may specify either all routes via the given gateway
	 * or a specific route entry actual NIDs) */

	lnet_net_lock(LNET_LOCK_EX);

	lpni = lnet_find_peer_ni_locked(gw_nid);
	if (lpni) {
		lp = lpni->lpni_peer_net->lpn_peer;
		LASSERT(lp);
		gw_nid = lp->lp_primary_nid;
		lnet_peer_ni_decref_locked(lpni);
	}

	if (net != LNET_NIDNET(LNET_NID_ANY)) {
		rnet = lnet_find_rnet_locked(net);
		if (!rnet) {
			lnet_net_unlock(LNET_LOCK_EX);
			return -ENOENT;
		}
		lnet_del_route_from_rnet(gw_nid, &rnet->lrn_routes,
					 &zombies);
		if (list_empty(&rnet->lrn_routes))
			list_move(&rnet->lrn_list, &rnet_zombies);
		goto delete_zombies;
	}

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++) {
		rn_list = &the_lnet.ln_remote_nets_hash[i];

		list_for_each_entry_safe(rnet, tmp, rn_list, lrn_list) {
			lnet_del_route_from_rnet(gw_nid, &rnet->lrn_routes,
						 &zombies);
			if (list_empty(&rnet->lrn_routes))
				list_move(&rnet->lrn_list, &rnet_zombies);
		}
	}

delete_zombies:
	lnet_net_unlock(LNET_LOCK_EX);

	while (!list_empty(&zombies)) {
		route = list_first_entry(&zombies, struct lnet_route, lr_list);
		list_del(&route->lr_list);
		LIBCFS_FREE(route, sizeof(*route));
	}

	while (!list_empty(&rnet_zombies)) {
		rnet = list_first_entry(&rnet_zombies, struct lnet_remotenet,
					lrn_list);
		list_del(&rnet->lrn_list);
		LIBCFS_FREE(rnet, sizeof(*rnet));
	}

	return 0;
}

void
lnet_destroy_routes (void)
{
	lnet_del_route(LNET_NIDNET(LNET_NID_ANY), LNET_NID_ANY);
}

int lnet_get_rtr_pool_cfg(int cpt, struct lnet_ioctl_pool_cfg *pool_cfg)
{
	struct lnet_rtrbufpool *rbp;
	int i, rc = -ENOENT, j;

	if (the_lnet.ln_rtrpools == NULL)
		return rc;


	cfs_percpt_for_each(rbp, i, the_lnet.ln_rtrpools) {
		if (i != cpt)
			continue;

		lnet_net_lock(i);
		for (j = 0; j < LNET_NRBPOOLS; j++) {
			pool_cfg->pl_pools[j].pl_npages = rbp[j].rbp_npages;
			pool_cfg->pl_pools[j].pl_nbuffers = rbp[j].rbp_nbuffers;
			pool_cfg->pl_pools[j].pl_credits = rbp[j].rbp_credits;
			pool_cfg->pl_pools[j].pl_mincredits = rbp[j].rbp_mincredits;
		}
		lnet_net_unlock(i);
		rc = 0;
		break;
	}

	lnet_net_lock(LNET_LOCK_EX);
	pool_cfg->pl_routing = the_lnet.ln_routing;
	lnet_net_unlock(LNET_LOCK_EX);

	return rc;
}

int
lnet_get_route(int idx, __u32 *net, __u32 *hops,
	       lnet_nid_t *gateway, __u32 *alive, __u32 *priority)
{
	struct list_head *e1;
	struct list_head *e2;
	struct lnet_remotenet *rnet;
	struct lnet_route	 *route;
	int		  cpt;
	int		  i;
	struct list_head *rn_list;

	cpt = lnet_net_lock_current();

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++) {
		rn_list = &the_lnet.ln_remote_nets_hash[i];
		list_for_each(e1, rn_list) {
			rnet = list_entry(e1, struct lnet_remotenet, lrn_list);

			list_for_each(e2, &rnet->lrn_routes) {
				route = list_entry(e2, struct lnet_route,
						   lr_list);

				if (idx-- == 0) {
					*net	  = rnet->lrn_net;
					*hops	  = route->lr_hops;
					*priority = route->lr_priority;
					*gateway  = route->lr_gateway->lp_primary_nid;
					*alive	  = lnet_is_route_alive(route);
					lnet_net_unlock(cpt);
					return 0;
				}
			}
		}
	}

	lnet_net_unlock(cpt);
	return -ENOENT;
}

static void
lnet_wait_known_routerstate(void)
{
	struct lnet_peer *rtr;
	struct list_head *entry;
	int all_known;

	LASSERT(the_lnet.ln_mt_state == LNET_MT_STATE_RUNNING);

	for (;;) {
		int cpt = lnet_net_lock_current();

		all_known = 1;
		list_for_each(entry, &the_lnet.ln_routers) {
			rtr = list_entry(entry, struct lnet_peer,
					 lp_rtr_list);

			spin_lock(&rtr->lp_lock);

			if ((rtr->lp_state & LNET_PEER_DISCOVERED) == 0) {
				all_known = 0;
				spin_unlock(&rtr->lp_lock);
				break;
			}
			spin_unlock(&rtr->lp_lock);
		}

		lnet_net_unlock(cpt);

		if (all_known)
			return;

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1));
	}
}

static void
lnet_update_ni_status_locked(void)
{
	struct lnet_ni *ni = NULL;
	time64_t now;
	time64_t timeout;

	LASSERT(the_lnet.ln_routing);

	timeout = router_ping_timeout +
		  MAX(live_router_check_interval, dead_router_check_interval);

	now = ktime_get_real_seconds();
	while ((ni = lnet_get_next_ni_locked(NULL, ni))) {
		if (ni->ni_net->net_lnd->lnd_type == LOLND)
			continue;

		if (now < ni->ni_last_alive + timeout)
			continue;

		lnet_ni_lock(ni);
		/* re-check with lock */
		if (now < ni->ni_last_alive + timeout) {
			lnet_ni_unlock(ni);
			continue;
		}

		LASSERT(ni->ni_status != NULL);

		if (ni->ni_status->ns_status != LNET_NI_STATUS_DOWN) {
			CDEBUG(D_NET, "NI(%s:%lld) status changed to down\n",
			       libcfs_nid2str(ni->ni_nid), timeout);
			/* NB: so far, this is the only place to set
			 * NI status to "down" */
			ni->ni_status->ns_status = LNET_NI_STATUS_DOWN;
		}
		lnet_ni_unlock(ni);
	}
}

void lnet_router_post_mt_start(void)
{
	if (check_routers_before_use) {
		/* Note that a helpful side-effect of pinging all known routers
		 * at startup is that it makes them drop stale connections they
		 * may have to a previous instance of me. */
		lnet_wait_known_routerstate();
	}
}

/*
 * This function is called from the monitor thread to check if there are
 * any active routers that need to be checked.
 */
inline bool
lnet_router_checker_active(void)
{
	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING)
		return true;

	/* Router Checker thread needs to run when routing is enabled in
	 * order to call lnet_update_ni_status_locked() */
	if (the_lnet.ln_routing)
		return true;

	return !list_empty(&the_lnet.ln_routers) &&
		(live_router_check_interval > 0 ||
		 dead_router_check_interval > 0);
}

void
lnet_check_routers(void)
{
	struct lnet_peer *rtr;
	struct list_head *entry;
	__u64	version;
	int	cpt;

	cpt = lnet_net_lock_current();
rescan:
	version = the_lnet.ln_routers_version;

	list_for_each(entry, &the_lnet.ln_routers) {
		rtr = list_entry(entry, struct lnet_peer,
				 lp_rtr_list);

		/* TODO use discovery to determine if router is alive */

		/* NB dropped lock */
		if (version != the_lnet.ln_routers_version) {
			/* the routers list has changed */
			goto rescan;
		}
	}

	if (the_lnet.ln_routing)
		lnet_update_ni_status_locked();

	lnet_net_unlock(cpt);
}

void
lnet_destroy_rtrbuf(struct lnet_rtrbuf *rb, int npages)
{
	int sz = offsetof(struct lnet_rtrbuf, rb_kiov[npages]);

	while (--npages >= 0)
		__free_page(rb->rb_kiov[npages].kiov_page);

	LIBCFS_FREE(rb, sz);
}

static struct lnet_rtrbuf *
lnet_new_rtrbuf(struct lnet_rtrbufpool *rbp, int cpt)
{
	int	       npages = rbp->rbp_npages;
	int	       sz = offsetof(struct lnet_rtrbuf, rb_kiov[npages]);
	struct page   *page;
	struct lnet_rtrbuf *rb;
	int	       i;

	LIBCFS_CPT_ALLOC(rb, lnet_cpt_table(), cpt, sz);
	if (rb == NULL)
		return NULL;

	rb->rb_pool = rbp;

	for (i = 0; i < npages; i++) {
		page = cfs_page_cpt_alloc(lnet_cpt_table(), cpt,
					  GFP_KERNEL | __GFP_ZERO);
		if (page == NULL) {
			while (--i >= 0)
				__free_page(rb->rb_kiov[i].kiov_page);

			LIBCFS_FREE(rb, sz);
			return NULL;
		}

		rb->rb_kiov[i].kiov_len = PAGE_SIZE;
		rb->rb_kiov[i].kiov_offset = 0;
		rb->rb_kiov[i].kiov_page = page;
	}

	return rb;
}

static void
lnet_rtrpool_free_bufs(struct lnet_rtrbufpool *rbp, int cpt)
{
	int npages = rbp->rbp_npages;
	struct lnet_rtrbuf *rb;
	struct list_head tmp;

	if (rbp->rbp_nbuffers == 0) /* not initialized or already freed */
		return;

	INIT_LIST_HEAD(&tmp);

	lnet_net_lock(cpt);
	list_splice_init(&rbp->rbp_msgs, &tmp);
	lnet_drop_routed_msgs_locked(&tmp, cpt);
	list_splice_init(&rbp->rbp_bufs, &tmp);
	rbp->rbp_req_nbuffers = 0;
	rbp->rbp_nbuffers = rbp->rbp_credits = 0;
	rbp->rbp_mincredits = 0;
	lnet_net_unlock(cpt);

	/* Free buffers on the free list. */
	while (!list_empty(&tmp)) {
		rb = list_entry(tmp.next, struct lnet_rtrbuf, rb_list);
		list_del(&rb->rb_list);
		lnet_destroy_rtrbuf(rb, npages);
	}
}

static int
lnet_rtrpool_adjust_bufs(struct lnet_rtrbufpool *rbp, int nbufs, int cpt)
{
	struct list_head rb_list;
	struct lnet_rtrbuf *rb;
	int		num_rb;
	int		num_buffers = 0;
	int		old_req_nbufs;
	int		npages = rbp->rbp_npages;

	lnet_net_lock(cpt);
	/* If we are called for less buffers than already in the pool, we
	 * just lower the req_nbuffers number and excess buffers will be
	 * thrown away as they are returned to the free list.  Credits
	 * then get adjusted as well.
	 * If we already have enough buffers allocated to serve the
	 * increase requested, then we can treat that the same way as we
	 * do the decrease. */
	num_rb = nbufs - rbp->rbp_nbuffers;
	if (nbufs <= rbp->rbp_req_nbuffers || num_rb <= 0) {
		rbp->rbp_req_nbuffers = nbufs;
		lnet_net_unlock(cpt);
		return 0;
	}
	/* store the older value of rbp_req_nbuffers and then set it to
	 * the new request to prevent lnet_return_rx_credits_locked() from
	 * freeing buffers that we need to keep around */
	old_req_nbufs = rbp->rbp_req_nbuffers;
	rbp->rbp_req_nbuffers = nbufs;
	lnet_net_unlock(cpt);

	INIT_LIST_HEAD(&rb_list);

	/* allocate the buffers on a local list first.	If all buffers are
	 * allocated successfully then join this list to the rbp buffer
	 * list.  If not then free all allocated buffers. */
	while (num_rb-- > 0) {
		rb = lnet_new_rtrbuf(rbp, cpt);
		if (rb == NULL) {
			CERROR("Failed to allocate %d route bufs of %d pages\n",
			       nbufs, npages);

			lnet_net_lock(cpt);
			rbp->rbp_req_nbuffers = old_req_nbufs;
			lnet_net_unlock(cpt);

			goto failed;
		}

		list_add(&rb->rb_list, &rb_list);
		num_buffers++;
	}

	lnet_net_lock(cpt);

	list_splice_tail(&rb_list, &rbp->rbp_bufs);
	rbp->rbp_nbuffers += num_buffers;
	rbp->rbp_credits += num_buffers;
	rbp->rbp_mincredits = rbp->rbp_credits;
	/* We need to schedule blocked msg using the newly
	 * added buffers. */
	while (!list_empty(&rbp->rbp_bufs) &&
	       !list_empty(&rbp->rbp_msgs))
		lnet_schedule_blocked_locked(rbp);

	lnet_net_unlock(cpt);

	return 0;

failed:
	while (!list_empty(&rb_list)) {
		rb = list_entry(rb_list.next, struct lnet_rtrbuf, rb_list);
		list_del(&rb->rb_list);
		lnet_destroy_rtrbuf(rb, npages);
	}

	return -ENOMEM;
}

static void
lnet_rtrpool_init(struct lnet_rtrbufpool *rbp, int npages)
{
	INIT_LIST_HEAD(&rbp->rbp_msgs);
	INIT_LIST_HEAD(&rbp->rbp_bufs);

	rbp->rbp_npages = npages;
	rbp->rbp_credits = 0;
	rbp->rbp_mincredits = 0;
}

void
lnet_rtrpools_free(int keep_pools)
{
	struct lnet_rtrbufpool *rtrp;
	int		  i;

	if (the_lnet.ln_rtrpools == NULL) /* uninitialized or freed */
		return;

	cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
		lnet_rtrpool_free_bufs(&rtrp[LNET_TINY_BUF_IDX], i);
		lnet_rtrpool_free_bufs(&rtrp[LNET_SMALL_BUF_IDX], i);
		lnet_rtrpool_free_bufs(&rtrp[LNET_LARGE_BUF_IDX], i);
	}

	if (!keep_pools) {
		cfs_percpt_free(the_lnet.ln_rtrpools);
		the_lnet.ln_rtrpools = NULL;
	}
}

static int
lnet_nrb_tiny_calculate(void)
{
	int	nrbs = LNET_NRB_TINY;

	if (tiny_router_buffers < 0) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "tiny_router_buffers=%d invalid when "
				   "routing enabled\n", tiny_router_buffers);
		return -EINVAL;
	}

	if (tiny_router_buffers > 0)
		nrbs = tiny_router_buffers;

	nrbs /= LNET_CPT_NUMBER;
	return max(nrbs, LNET_NRB_TINY_MIN);
}

static int
lnet_nrb_small_calculate(void)
{
	int	nrbs = LNET_NRB_SMALL;

	if (small_router_buffers < 0) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "small_router_buffers=%d invalid when "
				   "routing enabled\n", small_router_buffers);
		return -EINVAL;
	}

	if (small_router_buffers > 0)
		nrbs = small_router_buffers;

	nrbs /= LNET_CPT_NUMBER;
	return max(nrbs, LNET_NRB_SMALL_MIN);
}

static int
lnet_nrb_large_calculate(void)
{
	int	nrbs = LNET_NRB_LARGE;

	if (large_router_buffers < 0) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "large_router_buffers=%d invalid when "
				   "routing enabled\n", large_router_buffers);
		return -EINVAL;
	}

	if (large_router_buffers > 0)
		nrbs = large_router_buffers;

	nrbs /= LNET_CPT_NUMBER;
	return max(nrbs, LNET_NRB_LARGE_MIN);
}

int
lnet_rtrpools_alloc(int im_a_router)
{
	struct lnet_rtrbufpool *rtrp;
	int	nrb_tiny;
	int	nrb_small;
	int	nrb_large;
	int	rc;
	int	i;

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

	nrb_tiny = lnet_nrb_tiny_calculate();
	if (nrb_tiny < 0)
		return -EINVAL;

	nrb_small = lnet_nrb_small_calculate();
	if (nrb_small < 0)
		return -EINVAL;

	nrb_large = lnet_nrb_large_calculate();
	if (nrb_large < 0)
		return -EINVAL;

	the_lnet.ln_rtrpools = cfs_percpt_alloc(lnet_cpt_table(),
						LNET_NRBPOOLS *
						sizeof(struct lnet_rtrbufpool));
	if (the_lnet.ln_rtrpools == NULL) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "Failed to initialize router buffe pool\n");
		return -ENOMEM;
	}

	cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
		lnet_rtrpool_init(&rtrp[LNET_TINY_BUF_IDX], 0);
		rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_TINY_BUF_IDX],
					      nrb_tiny, i);
		if (rc != 0)
			goto failed;

		lnet_rtrpool_init(&rtrp[LNET_SMALL_BUF_IDX],
				  LNET_NRB_SMALL_PAGES);
		rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_SMALL_BUF_IDX],
					      nrb_small, i);
		if (rc != 0)
			goto failed;

		lnet_rtrpool_init(&rtrp[LNET_LARGE_BUF_IDX],
				  LNET_NRB_LARGE_PAGES);
		rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_LARGE_BUF_IDX],
					      nrb_large, i);
		if (rc != 0)
			goto failed;
	}

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_routing = 1;
	lnet_net_unlock(LNET_LOCK_EX);
	wake_up(&the_lnet.ln_mt_waitq);
	return 0;

 failed:
	lnet_rtrpools_free(0);
	return rc;
}

static int
lnet_rtrpools_adjust_helper(int tiny, int small, int large)
{
	int nrb = 0;
	int rc = 0;
	int i;
	struct lnet_rtrbufpool *rtrp;

	/* If the provided values for each buffer pool are different than the
	 * configured values, we need to take action. */
	if (tiny >= 0) {
		tiny_router_buffers = tiny;
		nrb = lnet_nrb_tiny_calculate();
		cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
			rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_TINY_BUF_IDX],
						      nrb, i);
			if (rc != 0)
				return rc;
		}
	}
	if (small >= 0) {
		small_router_buffers = small;
		nrb = lnet_nrb_small_calculate();
		cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
			rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_SMALL_BUF_IDX],
						      nrb, i);
			if (rc != 0)
				return rc;
		}
	}
	if (large >= 0) {
		large_router_buffers = large;
		nrb = lnet_nrb_large_calculate();
		cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
			rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_LARGE_BUF_IDX],
						      nrb, i);
			if (rc != 0)
				return rc;
		}
	}

	return 0;
}

int
lnet_rtrpools_adjust(int tiny, int small, int large)
{
	/* this function doesn't revert the changes if adding new buffers
	 * failed.  It's up to the user space caller to revert the
	 * changes. */

	if (!the_lnet.ln_routing)
		return 0;

	return lnet_rtrpools_adjust_helper(tiny, small, large);
}

int
lnet_rtrpools_enable(void)
{
	int rc = 0;

	if (the_lnet.ln_routing)
		return 0;

	if (the_lnet.ln_rtrpools == NULL)
		/* If routing is turned off, and we have never
		 * initialized the pools before, just call the
		 * standard buffer pool allocation routine as
		 * if we are just configuring this for the first
		 * time. */
		rc = lnet_rtrpools_alloc(1);
	else
		rc = lnet_rtrpools_adjust_helper(0, 0, 0);
	if (rc != 0)
		return rc;

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_routing = 1;

	the_lnet.ln_ping_target->pb_info.pi_features &=
		~LNET_PING_FEAT_RTE_DISABLED;
	lnet_net_unlock(LNET_LOCK_EX);

	return rc;
}

void
lnet_rtrpools_disable(void)
{
	if (!the_lnet.ln_routing)
		return;

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_routing = 0;
	the_lnet.ln_ping_target->pb_info.pi_features |=
		LNET_PING_FEAT_RTE_DISABLED;

	tiny_router_buffers = 0;
	small_router_buffers = 0;
	large_router_buffers = 0;
	lnet_net_unlock(LNET_LOCK_EX);
	lnet_rtrpools_free(1);
}

static inline void
lnet_notify_peer_down(struct lnet_ni *ni, lnet_nid_t nid)
{
	if (ni->ni_net->net_lnd->lnd_notify_peer_down != NULL)
		(ni->ni_net->net_lnd->lnd_notify_peer_down)(nid);
}

/*
 * ni: local NI used to communicate with the peer
 * nid: peer NID
 * alive: true if peer is alive, false otherwise
 * reset: reset health value. This is requested by the LND.
 * when: notificaiton time.
 */
int
lnet_notify(struct lnet_ni *ni, lnet_nid_t nid, bool alive, bool reset,
	    time64_t when)
{
	struct lnet_peer_ni *lpni = NULL;
	time64_t now = ktime_get_seconds();
	int cpt;

	LASSERT (!in_interrupt ());

	CDEBUG (D_NET, "%s notifying %s: %s\n",
		(ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
		libcfs_nid2str(nid),
		alive ? "up" : "down");

	if (ni != NULL &&
	    LNET_NIDNET(ni->ni_nid) != LNET_NIDNET(nid)) {
		CWARN("Ignoring notification of %s %s by %s (different net)\n",
		      libcfs_nid2str(nid), alive ? "birth" : "death",
		      libcfs_nid2str(ni->ni_nid));
		return -EINVAL;
	}

	/* can't do predictions... */
	if (when > now) {
		CWARN("Ignoring prediction from %s of %s %s "
		      "%lld seconds in the future\n",
		      (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
		      libcfs_nid2str(nid), alive ? "up" : "down", when - now);
		return -EINVAL;
	}

	if (ni != NULL && !alive &&		/* LND telling me she's down */
	    !auto_down) {			/* auto-down disabled */
		CDEBUG(D_NET, "Auto-down disabled\n");
		return 0;
	}

	/* must lock 0 since this is used for synchronization */
	lnet_net_lock(0);

	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		lnet_net_unlock(0);
		return -ESHUTDOWN;
	}

	lpni = lnet_find_peer_ni_locked(nid);
	if (lpni == NULL) {
		/* nid not found */
		lnet_net_unlock(0);
		CDEBUG(D_NET, "%s not found\n", libcfs_nid2str(nid));
		return 0;
	}

	if (alive) {
		if (reset)
			lnet_set_healthv(&lpni->lpni_healthv,
					 LNET_MAX_HEALTH_VALUE);
		else
			lnet_inc_healthv(&lpni->lpni_healthv);
	} else {
		lnet_handle_remote_failure_locked(lpni);
	}

	/* recalculate aliveness */
	alive = lnet_is_peer_ni_alive(lpni);
	lnet_net_unlock(0);

	if (ni != NULL && !alive)
		lnet_notify_peer_down(ni, lpni->lpni_nid);

	cpt = lpni->lpni_cpt;
	lnet_net_lock(cpt);
	lnet_peer_ni_decref_locked(lpni);
	lnet_net_unlock(cpt);

	return 0;
}
EXPORT_SYMBOL(lnet_notify);
