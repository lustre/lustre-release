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

int dead_router_check_interval = INT_MIN;
module_param(dead_router_check_interval, int, 0444);
MODULE_PARM_DESC(dead_router_check_interval, "(DEPRECATED - Use alive_router_check_interval)");

int live_router_check_interval = INT_MIN;
module_param(live_router_check_interval, int, 0444);
MODULE_PARM_DESC(live_router_check_interval, "(DEPRECATED - Use alive_router_check_interval)");

int alive_router_check_interval = 60;
module_param(alive_router_check_interval, int, 0644);
MODULE_PARM_DESC(alive_router_check_interval, "Seconds between live router health checks (<= 0 to disable)");

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

static void lnet_add_route_to_rnet(struct lnet_remotenet *rnet,
				   struct lnet_route *route);
static void lnet_del_route_from_rnet(lnet_nid_t gw_nid, struct list_head *route_list,
				     struct list_head *zombies);

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

void
lnet_move_route(struct lnet_route *route, struct lnet_peer *lp,
		struct list_head *rt_list)
{
	struct lnet_remotenet *rnet;
	struct list_head zombies;
	struct list_head *l;

	INIT_LIST_HEAD(&zombies);

	if (rt_list)
		l = rt_list;
	else
		l = &zombies;

	rnet = lnet_find_rnet_locked(route->lr_net);
	LASSERT(rnet);

	CDEBUG(D_NET, "deleting route %s->%s\n",
	       libcfs_net2str(route->lr_net),
	       libcfs_nid2str(route->lr_nid));

	/*
	 * use the gateway's lp_primary_nid to delete the route as the
	 * lr_nid can be a constituent NID of the peer
	 */
	lnet_del_route_from_rnet(route->lr_gateway->lp_primary_nid,
				 &rnet->lrn_routes, l);

	if (lp) {
		route = list_first_entry(l, struct lnet_route,
					lr_list);
		route->lr_gateway = lp;
		lnet_add_route_to_rnet(rnet, route);
	} else {
		while (!list_empty(l) && !rt_list) {
			route = list_first_entry(l, struct lnet_route,
				 lr_list);
			list_del(&route->lr_list);
			LIBCFS_FREE(route, sizeof(*route));
		}
	}
}

void
lnet_rtr_transfer_to_peer(struct lnet_peer *src, struct lnet_peer *target)
{
	struct lnet_route *route;
	struct lnet_route *tmp, *tmp2;

	lnet_net_lock(LNET_LOCK_EX);
	CDEBUG(D_NET, "transfering routes from %s -> %s\n",
	       libcfs_nid2str(src->lp_primary_nid),
	       libcfs_nid2str(target->lp_primary_nid));
	list_for_each_entry(route, &src->lp_routes, lr_gwlist) {
		CDEBUG(D_NET, "%s: %s->%s\n", libcfs_nid2str(src->lp_primary_nid),
		       libcfs_net2str(route->lr_net),
		       libcfs_nid2str(route->lr_nid));
	}
	list_splice_init(&src->lp_rtrq, &target->lp_rtrq);
	list_for_each_entry_safe(route, tmp, &src->lp_routes, lr_gwlist) {
		struct lnet_route *r2;
		bool present = false;
		list_for_each_entry_safe(r2, tmp2, &target->lp_routes, lr_gwlist) {
			if (route->lr_net == r2->lr_net) {
				if (route->lr_priority >= r2->lr_priority)
					present = true;
				else if (route->lr_hops >= r2->lr_hops)
					present = true;
				else
					lnet_move_route(r2, NULL, NULL);
			}
		}
		if (present)
			lnet_move_route(route, NULL, NULL);
		else
			lnet_move_route(route, target, NULL);
	}

	if (list_empty(&target->lp_rtr_list)) {
		lnet_peer_addref_locked(target);
		list_add_tail(&target->lp_rtr_list, &the_lnet.ln_routers);
	}

	the_lnet.ln_routers_version++;
	lnet_net_unlock(LNET_LOCK_EX);
}

int
lnet_peers_start_down(void)
{
	return check_routers_before_use;
}

/*
 * The peer_net of a gateway is alive if at least one of the peer_ni's on
 * that peer_net is alive.
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

	if (!gw->lp_alive)
		return false;

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

	/* If the gateway is down then all routes are considered down */
	if (!gw->lp_alive)
		return false;

	/*
	 * if discovery is disabled then rely on the cached aliveness
	 * information. This is handicapped information which we log when
	 * we receive the discovery ping response. The most uptodate
	 * aliveness information can only be obtained when discovery is
	 * enabled.
	 */
	if (lnet_is_discovery_disabled(gw))
		return atomic_read(&route->lr_alive) == 1;

	/*
	 * check the gateway's interfaces on the local network
	 */
	llpn = lnet_peer_get_net_locked(gw, route->lr_lnet);
	if (!llpn)
		return false;

	if (!lnet_is_gateway_net_alive(llpn))
		return false;

	/*
	 * For single hop routes avoid_asym_router_failure dictates
	 * that the remote net must exist on the gateway. For multi-hop
	 * routes the next-hop will not have the remote net.
	 */
	if (avoid_asym_router_failure &&
	    (route->lr_hops == 1 || route->lr_hops == LNET_UNDEFINED_HOPS)) {
		rlpn = lnet_peer_get_net_locked(gw, route->lr_net);
		if (!rlpn)
			return false;
		if (!lnet_is_gateway_net_alive(rlpn))
			return false;
	}

	spin_lock(&gw->lp_lock);
	if (!(gw->lp_state & LNET_PEER_ROUTER_ENABLED)) {
		spin_unlock(&gw->lp_lock);
		if (gw->lp_rtr_refcount > 0)
			CERROR("peer %s is being used as a gateway but routing feature is not turned on\n",
			       libcfs_nid2str(gw->lp_primary_nid));
		return false;
	}
	spin_unlock(&gw->lp_lock);

	return true;
}

void
lnet_consolidate_routes_locked(struct lnet_peer *orig_lp,
			       struct lnet_peer *new_lp)
{
	struct lnet_peer_ni *lpni;
	struct lnet_route *route;

	/*
	 * Although a route is correlated with a peer, but when it's added
	 * a specific NID is used. That NID refers to a peer_ni within
	 * a peer. There could be other peer_nis on the same net, which
	 * can be used to send to that gateway. However when we are
	 * consolidating gateways because of discovery, the nid used to
	 * add the route might've moved between gateway peers. In this
	 * case we want to move the route to the new gateway as well. The
	 * intent here is not to confuse the user who added the route.
	 */
	list_for_each_entry(route, &orig_lp->lp_routes, lr_gwlist) {
		lpni = lnet_peer_get_ni_locked(orig_lp, route->lr_nid);
		if (!lpni) {
			lnet_net_lock(LNET_LOCK_EX);
			list_move(&route->lr_gwlist, &new_lp->lp_routes);
			lnet_net_unlock(LNET_LOCK_EX);
		}
	}
}

static inline void
lnet_check_route_inconsistency(struct lnet_route *route)
{
	if (!route->lr_single_hop &&
	    (route->lr_hops == 1 || route->lr_hops == LNET_UNDEFINED_HOPS)) {
		CWARN("route %s->%s is detected to be multi-hop but hop count is set to %d\n",
			libcfs_net2str(route->lr_net),
			libcfs_nid2str(route->lr_gateway->lp_primary_nid),
			(int) route->lr_hops);
	}
}

static void
lnet_set_route_hop_type(struct lnet_peer *gw, struct lnet_route *route)
{
	struct lnet_peer_net *lpn;
	bool single_hop = false;

	list_for_each_entry(lpn, &gw->lp_peer_nets, lpn_peer_nets) {
		if (route->lr_net == lpn->lpn_net_id) {
			single_hop = true;
			break;
		}
	}
	route->lr_single_hop = single_hop;
	lnet_check_route_inconsistency(route);
}

/* Must hold net_lock/EX */
void
lnet_router_discovery_ping_reply(struct lnet_peer *lp)
{
	struct lnet_ping_buffer *pbuf = lp->lp_data;
	struct lnet_peer_net *llpn;
	struct lnet_route *route;
	bool single_hop = false;
	bool net_up = false;
	unsigned lp_state;
	__u32 net;
	int i;


	spin_lock(&lp->lp_lock);
	lp_state = lp->lp_state;

	/* only handle replies if discovery is disabled. */
	if (!lnet_is_discovery_disabled_locked(lp)) {
		spin_unlock(&lp->lp_lock);
		return;
	}

	spin_unlock(&lp->lp_lock);

	if (lp_state & LNET_PEER_PING_FAILED ||
	    pbuf->pb_info.pi_features & LNET_PING_FEAT_RTE_DISABLED) {
		CDEBUG(D_NET, "Set routes down for gw %s because %s %d\n",
		       libcfs_nid2str(lp->lp_primary_nid),
		       lp_state & LNET_PEER_PING_FAILED ? "ping failed" :
		       "route feature is disabled", lp->lp_ping_error);
		/* If the ping failed or the peer has routing disabled then
		 * mark the routes served by this peer down
		 */
		list_for_each_entry(route, &lp->lp_routes, lr_gwlist)
			lnet_set_route_aliveness(route, false);
		return;
	}

	CDEBUG(D_NET, "Discovery is disabled. Processing reply for gw: %s:%d\n",
	       libcfs_nid2str(lp->lp_primary_nid), pbuf->pb_info.pi_nnis);

	/*
	 * examine the ping response to determine if the routes on that
	 * gateway should be declared alive.
	 * The route is alive if:
	 *  1. local network to reach the route is alive and
	 *  2. route is single hop, avoid_async_router_failure is set and
	 *     there exists at least one NI on the route's remote net
	 */
	list_for_each_entry(route, &lp->lp_routes, lr_gwlist) {
		llpn = lnet_peer_get_net_locked(lp, route->lr_lnet);
		if (!llpn) {
			lnet_set_route_aliveness(route, false);
			continue;
		}

		if (!lnet_is_gateway_net_alive(llpn)) {
			lnet_set_route_aliveness(route, false);
			continue;
		}

		single_hop = net_up = false;
		for (i = 1; i < pbuf->pb_info.pi_nnis; i++) {
			net = LNET_NIDNET(pbuf->pb_info.pi_ni[i].ns_nid);

			if (route->lr_net == net) {
				single_hop = true;
				if (pbuf->pb_info.pi_ni[i].ns_status ==
				    LNET_NI_STATUS_UP) {
					net_up = true;
					break;
				}
			}
		}

		route->lr_single_hop = single_hop;
		if (avoid_asym_router_failure &&
		    (route->lr_hops == 1 ||
		     route->lr_hops == LNET_UNDEFINED_HOPS))
			lnet_set_route_aliveness(route, net_up);
		else
			lnet_set_route_aliveness(route, true);

		/*
		 * warn that the route is configured as single-hop but it
		 * really is multi-hop as far as we can tell.
		 */
		lnet_check_route_inconsistency(route);
	}
}

void
lnet_router_discovery_complete(struct lnet_peer *lp)
{
	struct lnet_peer_ni *lpni = NULL;
	struct lnet_route *route;

	spin_lock(&lp->lp_lock);
	lp->lp_state &= ~LNET_PEER_RTR_DISCOVERY;
	lp->lp_state |= LNET_PEER_RTR_DISCOVERED;
	lp->lp_alive = lp->lp_dc_error == 0;
	spin_unlock(&lp->lp_lock);

	if (!lp->lp_dc_error) {
		/* ping replies are being handled when discovery is disabled */
		if (lnet_is_discovery_disabled_locked(lp))
			return;

		/*
		* mark single-hop routes.  If the remote net is not configured on
		* the gateway we assume this is intentional and we mark the
		* gateway as multi-hop
		*/
		list_for_each_entry(route, &lp->lp_routes, lr_gwlist) {
			lnet_set_route_aliveness(route, true);
			lnet_set_route_hop_type(lp, route);
		}

		return;
	}

	/*
	 * We do not send messages directly to the remote interfaces
	 * of an LNet router. As such, we rely on the PING response
	 * to determine the up/down status of these interfaces. If
	 * a PING response is not receieved, or some other problem with
	 * discovery occurs that prevents us from getting this status,
	 * we assume all interfaces are down until we're able to
	 * determine otherwise.
	 */
	CDEBUG(D_NET, "%s: Router discovery failed %d\n",
	       libcfs_nid2str(lp->lp_primary_nid), lp->lp_dc_error);
	while ((lpni = lnet_get_next_peer_ni_locked(lp, NULL, lpni)) != NULL)
		lpni->lpni_ns_status = LNET_NI_STATUS_DOWN;

	list_for_each_entry(route, &lp->lp_routes, lr_gwlist)
		lnet_set_route_aliveness(route, false);
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
}

/* NB expects LNET_LOCK held */
static void
lnet_add_route_to_rnet(struct lnet_remotenet *rnet, struct lnet_route *route)
{
	struct lnet_peer_net *lpn;
	unsigned int offset = 0;
	unsigned int len = 0;
	struct list_head *e;
	time64_t now;

	lnet_shuffle_seed();

	list_for_each(e, &rnet->lrn_routes)
		len++;

	/*
	 * Randomly adding routes to the list is done to ensure that when
	 * different nodes are using the same list of routers, they end up
	 * preferring different routers.
	 */
	offset = prandom_u32_max(len + 1);
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
	now = ktime_get_real_seconds();
	list_for_each_entry(lpn, &route->lr_gateway->lp_peer_nets,
			    lpn_peer_nets) {
		lpn->lpn_next_ping = now;
	}

	the_lnet.ln_remote_nets_version++;

	/* add the route on the gateway list */
	list_add(&route->lr_gwlist, &route->lr_gateway->lp_routes);

	/* take a router reference count on the gateway */
	lnet_rtr_addref_locked(route->lr_gateway);
}

int
lnet_add_route(__u32 net, __u32 hops, lnet_nid_t gateway,
	       __u32 priority, __u32 sensitivity)
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
	    gateway == LNET_NID_LO_0 ||
	    net == LNET_NET_ANY ||
	    LNET_NETTYP(net) == LOLND ||
	    LNET_NIDNET(gateway) == net ||
	    (hops != LNET_UNDEFINED_HOPS && (hops < 1 || hops > 255)))
		return -EINVAL;

	/* it's a local network */
	if (lnet_islocalnet(net))
		return -EEXIST;

	if (!lnet_islocalnet(LNET_NIDNET(gateway))) {
		CERROR("Cannot add route with gateway %s. There is no local interface configured on LNet %s\n",
		       libcfs_nid2str(gateway),
		       libcfs_net2str(LNET_NIDNET(gateway)));
		return -EHOSTUNREACH;
	}

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
	route->lr_nid = gateway;
	route->lr_priority = priority;
	route->lr_hops = hops;
	if (lnet_peers_start_down())
		atomic_set(&route->lr_alive, 0);
	else
		atomic_set(&route->lr_alive, 1);

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
	if (add_route) {
		gw->lp_health_sensitivity = sensitivity;
		lnet_add_route_to_rnet(rnet2, route);
		if (lnet_peer_discovery_disabled)
			CWARN("Consider turning discovery on to enable full "
			      "Multi-Rail routing functionality\n");
	}

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
	complete(&the_lnet.ln_mt_wait_complete);

	return rc;
}

void
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
	LIST_HEAD(rnet_zombies);
	struct lnet_remotenet *rnet;
	struct lnet_remotenet *tmp;
	struct list_head *rn_list;
	struct lnet_peer_ni *lpni;
	struct lnet_route *route;
	LIST_HEAD(zombies);
	struct lnet_peer *lp = NULL;
	int i = 0;

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

	if (net != LNET_NET_ANY) {
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
	/*
	 * check if there are any routes remaining on the gateway
	 * If there are no more routes make sure to set the peer's
	 * lp_disc_net_id to 0 (invalid), in case we add more routes in
	 * the future on that gateway, then we start our discovery process
	 * from scratch
	 */
	if (lpni) {
		if (list_empty(&lp->lp_routes))
			lp->lp_disc_net_id = 0;
	}

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
	lnet_del_route(LNET_NET_ANY, LNET_NID_ANY);
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
	       lnet_nid_t *gateway, __u32 *flags, __u32 *priority, __u32 *sensitivity)
{
	struct lnet_remotenet *rnet;
	struct list_head *rn_list;
	struct lnet_route *route;
	struct list_head *e1;
	struct list_head *e2;
	int cpt;
	int i;

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
					*gateway  = route->lr_nid;
					*hops	  = route->lr_hops;
					*priority = route->lr_priority;
					*sensitivity = route->lr_gateway->
						lp_health_sensitivity;
					if (lnet_is_route_alive(route))
						*flags |= LNET_RT_ALIVE;
					else
						*flags &= ~LNET_RT_ALIVE;
					if (route->lr_single_hop)
						*flags &= ~LNET_RT_MULTI_HOP;
					else
						*flags |= LNET_RT_MULTI_HOP;
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

			if ((rtr->lp_state & LNET_PEER_RTR_DISCOVERED) == 0) {
				all_known = 0;
				spin_unlock(&rtr->lp_lock);
				break;
			}
			spin_unlock(&rtr->lp_lock);
		}

		lnet_net_unlock(cpt);

		if (all_known)
			return;

		schedule_timeout_uninterruptible(cfs_time_seconds(1));
	}
}

static inline bool
lnet_net_set_status_locked(struct lnet_net *net, __u32 status)
{
	struct lnet_ni *ni;
	bool update = false;

	list_for_each_entry(ni, &net->net_ni_list, ni_netlist)
		if (lnet_ni_set_status(ni, status))
			update = true;

	return update;
}

static bool
lnet_update_ni_status_locked(void)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	bool push = false;
	time64_t now;
	time64_t timeout;

	LASSERT(the_lnet.ln_routing);

	timeout = router_ping_timeout + alive_router_check_interval;

	now = ktime_get_real_seconds();
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (net->net_lnd->lnd_type == LOLND)
			continue;

		if (now < net->net_last_alive + timeout)
			goto check_ni_fatal;

		spin_lock(&net->net_lock);
		/* re-check with lock */
		if (now < net->net_last_alive + timeout) {
			spin_unlock(&net->net_lock);
			goto check_ni_fatal;
		}
		spin_unlock(&net->net_lock);

		/*
		 * if the net didn't receive any traffic for past the
		 * timeout on any of its constituent NIs, then mark all
		 * the NIs down.
		 */
		if (lnet_net_set_status_locked(net, LNET_NI_STATUS_DOWN)) {
			push = true;
			continue;
		}

check_ni_fatal:
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			/* lnet_ni_set_status() will perform the same check of
			 * ni_status while holding the ni lock. We can safely
			 * check ni_status without that lock because it is only
			 * written to under net_lock/EX and our caller is
			 * holding a net lock.
			 */
			if (atomic_read(&ni->ni_fatal_error_on) &&
			    ni->ni_status &&
			    ni->ni_status->ns_status != LNET_NI_STATUS_DOWN &&
			    lnet_ni_set_status(ni, LNET_NI_STATUS_DOWN))
				push = true;
		}
	}

	return push;
}

void lnet_wait_router_start(void)
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
bool lnet_router_checker_active(void)
{
	/* Router Checker thread needs to run when routing is enabled in
	 * order to call lnet_update_ni_status_locked() */
	if (the_lnet.ln_routing)
		return true;

	return !list_empty(&the_lnet.ln_routers) &&
		alive_router_check_interval > 0;
}

void
lnet_check_routers(void)
{
	struct lnet_peer_net *first_lpn;
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;
	struct list_head *entry;
	struct lnet_peer *rtr;
	bool push = false;
	bool needs_ping;
	bool found_lpn;
	__u64 version;
	__u32 net_id;
	time64_t now;
	int cpt;
	int rc;

	cpt = lnet_net_lock_current();
rescan:
	version = the_lnet.ln_routers_version;

	list_for_each(entry, &the_lnet.ln_routers) {
		rtr = list_entry(entry, struct lnet_peer,
				 lp_rtr_list);

		/* If we're currently discovering the peer then don't
		 * issue another discovery
		 */
		if (rtr->lp_state & LNET_PEER_RTR_DISCOVERY)
			continue;

		now = ktime_get_real_seconds();

		/* find the next local peer net which needs to be ping'd */
		needs_ping = false;
		first_lpn = NULL;
		found_lpn = false;
		net_id = rtr->lp_disc_net_id;
		do {
			lpn = lnet_get_next_peer_net_locked(rtr, net_id);
			if (!lpn) {
				CERROR("gateway %s has no networks\n",
				libcfs_nid2str(rtr->lp_primary_nid));
				break;
			}

			/* We looped back to the first peer net */
			if (first_lpn == lpn)
				break;
			if (!first_lpn)
				first_lpn = lpn;

			net_id = lpn->lpn_net_id;
			if (!lnet_islocalnet_locked(net_id))
				continue;

			found_lpn = true;

			CDEBUG(D_NET, "rtr %s(%p) %s(%p) next ping %lld\n",
			       libcfs_nid2str(rtr->lp_primary_nid), rtr,
			       libcfs_net2str(net_id), lpn,
			       lpn->lpn_next_ping);

			needs_ping = now >= lpn->lpn_next_ping;

		} while (!needs_ping);

		if (!found_lpn || !lpn) {
			CERROR("no local network found for gateway %s\n",
			       libcfs_nid2str(rtr->lp_primary_nid));
			continue;
		}

		if (!needs_ping)
			continue;

		spin_lock(&rtr->lp_lock);
		/* make sure we fully discover the router */
		rtr->lp_state &= ~LNET_PEER_NIDS_UPTODATE;
		rtr->lp_state |= LNET_PEER_FORCE_PING | LNET_PEER_FORCE_PUSH |
			LNET_PEER_RTR_DISCOVERY;
		spin_unlock(&rtr->lp_lock);

		/* find the peer_ni associated with the primary NID */
		lpni = lnet_peer_get_ni_locked(rtr, rtr->lp_primary_nid);
		if (!lpni) {
			CDEBUG(D_NET, "Expected to find an lpni for %s, but non found\n",
			       libcfs_nid2str(rtr->lp_primary_nid));
			continue;
		}
		lnet_peer_ni_addref_locked(lpni);

		/* specify the net to use */
		rtr->lp_disc_net_id = lpn->lpn_net_id;

		/* discover the router */
		CDEBUG(D_NET, "discover %s, cpt = %d\n",
		       libcfs_nid2str(lpni->lpni_nid), cpt);
		rc = lnet_discover_peer_locked(lpni, cpt, false);

		/* drop ref taken above */
		lnet_peer_ni_decref_locked(lpni);

		if (!rc)
			lpn->lpn_next_ping = now + alive_router_check_interval;
		else
			CERROR("Failed to discover router %s\n",
			       libcfs_nid2str(rtr->lp_primary_nid));

		/* NB cpt lock was dropped in lnet_discover_peer_locked() */
		if (version != the_lnet.ln_routers_version) {
			/* the routers list has changed */
			goto rescan;
		}
	}

	if (the_lnet.ln_routing)
		push = lnet_update_ni_status_locked();

	lnet_net_unlock(cpt);

	/* if the status of the ni changed update the peers */
	if (push)
		lnet_push_update_to_peers(1);
}

void
lnet_destroy_rtrbuf(struct lnet_rtrbuf *rb, int npages)
{
	int sz = offsetof(struct lnet_rtrbuf, rb_kiov[npages]);

	while (--npages >= 0)
		__free_page(rb->rb_kiov[npages].bv_page);

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
				__free_page(rb->rb_kiov[i].bv_page);

			LIBCFS_FREE(rb, sz);
			return NULL;
		}

		rb->rb_kiov[i].bv_len = PAGE_SIZE;
		rb->rb_kiov[i].bv_offset = 0;
		rb->rb_kiov[i].bv_page = page;
	}

	return rb;
}

static void
lnet_rtrpool_free_bufs(struct lnet_rtrbufpool *rbp, int cpt)
{
	int npages = rbp->rbp_npages;
	struct lnet_rtrbuf *rb;
	LIST_HEAD(tmp);

	if (rbp->rbp_nbuffers == 0) /* not initialized or already freed */
		return;

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
	LIST_HEAD(rb_list);
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
	complete(&the_lnet.ln_mt_wait_complete);
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

	if (lnet_peer_discovery_disabled)
		CWARN("Consider turning discovery on to enable full "
		      "Multi-Rail routing functionality\n");

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
	struct lnet_route *route;
	struct lnet_peer *lp;
	time64_t now = ktime_get_seconds();
	int cpt;

	LASSERT(!in_interrupt());

	CDEBUG(D_NET, "%s notifying %s: %s\n",
	       (ni == NULL) ? "userspace" : libcfs_nid2str(ni->ni_nid),
	       libcfs_nid2str(nid), alive ? "up" : "down");

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
		if (reset) {
			lpni->lpni_ns_status = LNET_NI_STATUS_UP;
			lnet_set_lpni_healthv_locked(lpni,
						     LNET_MAX_HEALTH_VALUE);
		} else {
			__u32 sensitivity = lpni->lpni_peer_net->
					lpn_peer->lp_health_sensitivity;

			lnet_inc_lpni_healthv_locked(lpni,
					(sensitivity) ? sensitivity :
					lnet_health_sensitivity);
		}
	} else if (reset) {
		lpni->lpni_ns_status = LNET_NI_STATUS_DOWN;
	}

	/* recalculate aliveness */
	alive = lnet_is_peer_ni_alive(lpni);

	lp = lpni->lpni_peer_net->lpn_peer;
	/* If this is an LNet router then update route aliveness */
	if (lp->lp_rtr_refcount) {
		if (reset)
			/* reset flag indicates gateway peer went up or down */
			lp->lp_alive = alive;

		/* If discovery is disabled, locally or on the gateway, then
		 * any routes using lpni as next-hop need to be updated
		 *
		 * NB: We can get many notifications while a route is down, so
		 * we try and avoid the expensive net_lock/EX here for the
		 * common case of receiving duplicate lnet_notify() calls (i.e.
		 * only grab EX lock when we actually need to update the route
		 * aliveness).
		 */
		if (lnet_is_discovery_disabled(lp)) {
			list_for_each_entry(route, &lp->lp_routes, lr_gwlist) {
				if (route->lr_nid == lpni->lpni_nid)
					lnet_set_route_aliveness(route, alive);
			}
		}
	}

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
