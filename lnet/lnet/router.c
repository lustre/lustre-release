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

int
lnet_peers_start_down(void)
{
	return check_routers_before_use;
}

void
lnet_notify_locked(struct lnet_peer_ni *lp, int notifylnd, int alive,
		   time64_t when)
{
	if (lp->lpni_timestamp > when) { /* out of date information */
		CDEBUG(D_NET, "Out of date\n");
		return;
	}

	/*
	 * This function can be called with different cpt locks being
	 * held. lpni_alive_count modification needs to be properly protected.
	 * Significant reads to lpni_alive_count are also protected with
	 * the same lock
	 */
	spin_lock(&lp->lpni_lock);

	lp->lpni_timestamp = when; /* update timestamp */
	lp->lpni_ping_deadline = 0;               /* disable ping timeout */

	if (lp->lpni_alive_count != 0 &&          /* got old news */
	    (!lp->lpni_alive) == (!alive)) {      /* new date for old news */
		spin_unlock(&lp->lpni_lock);
		CDEBUG(D_NET, "Old news\n");
		return;
	}

	/* Flag that notification is outstanding */

	lp->lpni_alive_count++;
	lp->lpni_alive = (alive) ? 1 : 0;
	lp->lpni_notify = 1;
	lp->lpni_notifylnd = notifylnd;
	if (lp->lpni_alive)
		lp->lpni_ping_feats = LNET_PING_FEAT_INVAL; /* reset */

	spin_unlock(&lp->lpni_lock);

	CDEBUG(D_NET, "set %s %d\n", libcfs_nid2str(lp->lpni_nid), alive);
}

/*
 * This function will always be called with lp->lpni_cpt lock held.
 */
static void
lnet_ni_notify_locked(struct lnet_ni *ni, struct lnet_peer_ni *lp)
{
	int alive;
	int notifylnd;

	/* Notify only in 1 thread at any time to ensure ordered notification.
	 * NB individual events can be missed; the only guarantee is that you
	 * always get the most recent news */

	spin_lock(&lp->lpni_lock);

	if (lp->lpni_notifying || ni == NULL) {
		spin_unlock(&lp->lpni_lock);
		return;
	}

	lp->lpni_notifying = 1;

	/*
	 * lp->lpni_notify needs to be protected because it can be set in
	 * lnet_notify_locked().
	 */
	while (lp->lpni_notify) {
		alive     = lp->lpni_alive;
		notifylnd = lp->lpni_notifylnd;

		lp->lpni_notifylnd = 0;
		lp->lpni_notify    = 0;

		if (notifylnd && ni->ni_net->net_lnd->lnd_notify != NULL) {
			spin_unlock(&lp->lpni_lock);
			lnet_net_unlock(lp->lpni_cpt);

			/* A new notification could happen now; I'll handle it
			 * when control returns to me */

			(ni->ni_net->net_lnd->lnd_notify)(ni, lp->lpni_nid,
							  alive);

			lnet_net_lock(lp->lpni_cpt);
			spin_lock(&lp->lpni_lock);
		}
	}

	lp->lpni_notifying = 0;
	spin_unlock(&lp->lpni_lock);
}

static void
lnet_rtr_addref_locked(struct lnet_peer_ni *lp)
{
	LASSERT(atomic_read(&lp->lpni_refcount) > 0);
	LASSERT(lp->lpni_rtr_refcount >= 0);

	/* lnet_net_lock must be exclusively locked */
	lp->lpni_rtr_refcount++;
	if (lp->lpni_rtr_refcount == 1) {
		struct list_head *pos;

		/* a simple insertion sort */
		list_for_each_prev(pos, &the_lnet.ln_routers) {
			struct lnet_peer_ni *rtr;

			rtr = list_entry(pos, struct lnet_peer_ni,
					 lpni_rtr_list);
			if (rtr->lpni_nid < lp->lpni_nid)
				break;
		}

		list_add(&lp->lpni_rtr_list, pos);
		/* addref for the_lnet.ln_routers */
		lnet_peer_ni_addref_locked(lp);
		the_lnet.ln_routers_version++;
	}
}

static void
lnet_rtr_decref_locked(struct lnet_peer_ni *lp)
{
	LASSERT(atomic_read(&lp->lpni_refcount) > 0);
	LASSERT(lp->lpni_rtr_refcount > 0);

	/* lnet_net_lock must be exclusively locked */
	lp->lpni_rtr_refcount--;
	if (lp->lpni_rtr_refcount == 0) {
		LASSERT(list_empty(&lp->lpni_routes));

		if (lp->lpni_rcd != NULL) {
			list_add(&lp->lpni_rcd->rcd_list,
				 &the_lnet.ln_rcd_deathrow);
			lp->lpni_rcd = NULL;
		}

		list_del(&lp->lpni_rtr_list);
		/* decref for the_lnet.ln_routers */
		lnet_peer_ni_decref_locked(lp);
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
	__u32 lnd_type;
	__u32 seed[2];
	struct timespec64 ts;
	struct lnet_ni *ni = NULL;

	if (seeded)
		return;

	cfs_get_random_bytes(seed, sizeof(seed));

	/* Nodes with small feet have little entropy
	 * the NID for this node gives the most entropy in the low bits */
	while ((ni = lnet_get_next_ni_locked(NULL, ni))) {
		lnd_type = LNET_NETTYP(LNET_NIDNET(ni->ni_nid));

		if (lnd_type != LOLND)
			seed[0] ^= (LNET_NIDADDR(ni->ni_nid) | lnd_type);
	}

	ktime_get_ts64(&ts);
	cfs_srand(ts.tv_sec ^ seed[0], ts.tv_nsec ^ seed[1]);
	seeded = 1;
	return;
}

/* NB expects LNET_LOCK held */
static void
lnet_add_route_to_rnet(struct lnet_remotenet *rnet, struct lnet_route *route)
{
	unsigned int	  len = 0;
	unsigned int	  offset = 0;
	struct list_head *e;

	lnet_shuffle_seed();

	list_for_each(e, &rnet->lrn_routes) {
		len++;
	}

	/* len+1 positions to add a new entry, also prevents division by 0 */
	offset = cfs_rand() % (len + 1);
	list_for_each(e, &rnet->lrn_routes) {
		if (offset == 0)
			break;
		offset--;
	}
	list_add(&route->lr_list, e);
	list_add(&route->lr_gwlist, &route->lr_gateway->lpni_routes);

	the_lnet.ln_remote_nets_version++;
	lnet_rtr_addref_locked(route->lr_gateway);
}

int
lnet_add_route(__u32 net, __u32 hops, lnet_nid_t gateway,
	       unsigned int priority)
{
	struct list_head	*e;
	struct lnet_remotenet	*rnet;
	struct lnet_remotenet	*rnet2;
	struct lnet_route		*route;
	struct lnet_ni		*ni;
	struct lnet_peer_ni	*lpni;
	int			add_route;
	int			rc;

	CDEBUG(D_NET, "Add route: net %s hops %d priority %u gw %s\n",
	       libcfs_net2str(net), hops, priority, libcfs_nid2str(gateway));

	if (gateway == LNET_NID_ANY ||
	    gateway == LNET_NID_LO_0 ||
	    net == LNET_NIDNET(LNET_NID_ANY) ||
	    LNET_NETTYP(net) == LOLND ||
	    LNET_NIDNET(gateway) == net ||
	    (hops != LNET_UNDEFINED_HOPS && (hops < 1 || hops > 255)))
		return -EINVAL;

	if (lnet_islocalnet(net))	/* it's a local network */
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
	route->lr_hops = hops;
	route->lr_net = net;
	route->lr_priority = priority;

	lnet_net_lock(LNET_LOCK_EX);

	lpni = lnet_nid2peerni_ex(gateway, LNET_LOCK_EX);
	if (IS_ERR(lpni)) {
		lnet_net_unlock(LNET_LOCK_EX);

		LIBCFS_FREE(route, sizeof(*route));
		LIBCFS_FREE(rnet, sizeof(*rnet));

		rc = PTR_ERR(lpni);
		if (rc == -EHOSTUNREACH) /* gateway is not on a local net. */
			return rc;	 /* ignore the route entry */
		CERROR("Error %d creating route %s %d %s\n", rc,
			libcfs_net2str(net), hops,
			libcfs_nid2str(gateway));
		return rc;
	}
	route->lr_gateway = lpni;
	LASSERT(the_lnet.ln_state == LNET_STATE_RUNNING);

	rnet2 = lnet_find_rnet_locked(net);
	if (rnet2 == NULL) {
		/* new network */
		list_add_tail(&rnet->lrn_list, lnet_net2rnethash(net));
		rnet2 = rnet;
	}

	/* Search for a duplicate route (it's a NOOP if it is) */
	add_route = 1;
	list_for_each(e, &rnet2->lrn_routes) {
		struct lnet_route *route2;

		route2 = list_entry(e, struct lnet_route, lr_list);
		if (route2->lr_gateway == route->lr_gateway) {
			add_route = 0;
			break;
		}

		/* our lookups must be true */
		LASSERT(route2->lr_gateway->lpni_nid != gateway);
	}

	if (add_route) {
		lnet_peer_ni_addref_locked(route->lr_gateway); /* +1 for notify */
		lnet_add_route_to_rnet(rnet2, route);

		ni = lnet_get_next_ni_locked(route->lr_gateway->lpni_net, NULL);
		lnet_net_unlock(LNET_LOCK_EX);

		/* XXX Assume alive */
		if (ni->ni_net->net_lnd->lnd_notify != NULL)
			(ni->ni_net->net_lnd->lnd_notify)(ni, gateway, 1);

		lnet_net_lock(LNET_LOCK_EX);
	}

	/* -1 for notify or !add_route */
	lnet_peer_ni_decref_locked(route->lr_gateway);
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

int
lnet_check_routes(void)
{
	struct lnet_remotenet *rnet;
	struct lnet_route	 *route;
	struct lnet_route	 *route2;
	struct list_head *e1;
	struct list_head *e2;
	int		  cpt;
	struct list_head *rn_list;
	int		  i;

	cpt = lnet_net_lock_current();

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++) {
		rn_list = &the_lnet.ln_remote_nets_hash[i];
		list_for_each(e1, rn_list) {
			rnet = list_entry(e1, struct lnet_remotenet, lrn_list);

			route2 = NULL;
			list_for_each(e2, &rnet->lrn_routes) {
				lnet_nid_t	nid1;
				lnet_nid_t	nid2;
				int		net;

				route = list_entry(e2, struct lnet_route,
						   lr_list);

				if (route2 == NULL) {
					route2 = route;
					continue;
				}

				if (route->lr_gateway->lpni_net ==
				    route2->lr_gateway->lpni_net)
					continue;

				nid1 = route->lr_gateway->lpni_nid;
				nid2 = route2->lr_gateway->lpni_nid;
				net = rnet->lrn_net;

				lnet_net_unlock(cpt);

				CERROR("Routes to %s via %s and %s not "
				       "supported\n",
				       libcfs_net2str(net),
				       libcfs_nid2str(nid1),
				       libcfs_nid2str(nid2));
				return -EINVAL;
			}
		}
	}

	lnet_net_unlock(cpt);
	return 0;
}

int
lnet_del_route(__u32 net, lnet_nid_t gw_nid)
{
	struct lnet_peer_ni	*gateway;
	struct lnet_remotenet	*rnet;
	struct lnet_route		*route;
	struct list_head	*e1;
	struct list_head	*e2;
	int			rc = -ENOENT;
	struct list_head	*rn_list;
	int			idx = 0;

	CDEBUG(D_NET, "Del route: net %s : gw %s\n",
	       libcfs_net2str(net), libcfs_nid2str(gw_nid));

	/* NB Caller may specify either all routes via the given gateway
	 * or a specific route entry actual NIDs) */

	lnet_net_lock(LNET_LOCK_EX);
	if (net == LNET_NIDNET(LNET_NID_ANY))
		rn_list = &the_lnet.ln_remote_nets_hash[0];
	else
		rn_list = lnet_net2rnethash(net);

again:
	list_for_each(e1, rn_list) {
		rnet = list_entry(e1, struct lnet_remotenet, lrn_list);

		if (!(net == LNET_NIDNET(LNET_NID_ANY) ||
			net == rnet->lrn_net))
			continue;

		list_for_each(e2, &rnet->lrn_routes) {
			route = list_entry(e2, struct lnet_route, lr_list);

			gateway = route->lr_gateway;
			if (!(gw_nid == LNET_NID_ANY ||
			      gw_nid == gateway->lpni_nid))
				continue;

			list_del(&route->lr_list);
			list_del(&route->lr_gwlist);
			the_lnet.ln_remote_nets_version++;

			if (list_empty(&rnet->lrn_routes))
				list_del(&rnet->lrn_list);
			else
				rnet = NULL;

			lnet_rtr_decref_locked(gateway);
			lnet_peer_ni_decref_locked(gateway);

			lnet_net_unlock(LNET_LOCK_EX);

			LIBCFS_FREE(route, sizeof(*route));

			if (rnet != NULL)
				LIBCFS_FREE(rnet, sizeof(*rnet));

			rc = 0;
			lnet_net_lock(LNET_LOCK_EX);
			goto again;
		}
	}

	if (net == LNET_NIDNET(LNET_NID_ANY) &&
	    ++idx < LNET_REMOTE_NETS_HASH_SIZE) {
		rn_list = &the_lnet.ln_remote_nets_hash[idx];
		goto again;
	}
	lnet_net_unlock(LNET_LOCK_EX);

	return rc;
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
					*gateway  = route->lr_gateway->lpni_nid;
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

void
lnet_swap_pinginfo(struct lnet_ping_buffer *pbuf)
{
	struct lnet_ni_status *stat;
	int nnis;
	int i;

	__swab32s(&pbuf->pb_info.pi_magic);
	__swab32s(&pbuf->pb_info.pi_features);
	__swab32s(&pbuf->pb_info.pi_pid);
	__swab32s(&pbuf->pb_info.pi_nnis);
	nnis = pbuf->pb_info.pi_nnis;
	if (nnis > pbuf->pb_nnis)
		nnis = pbuf->pb_nnis;
	for (i = 0; i < nnis; i++) {
		stat = &pbuf->pb_info.pi_ni[i];
		__swab64s(&stat->ns_nid);
		__swab32s(&stat->ns_status);
	}
	return;
}

/**
 * parse router-checker pinginfo, record number of down NIs for remote
 * networks on that router.
 */
static void
lnet_parse_rc_info(struct lnet_rc_data *rcd)
{
	struct lnet_ping_buffer	*pbuf = rcd->rcd_pingbuffer;
	struct lnet_peer_ni	*gw   = rcd->rcd_gateway;
	struct lnet_route		*rte;
	int			nnis;

	if (!gw->lpni_alive || !pbuf)
		return;

	/*
	 * Protect gw->lpni_ping_feats. This can be set from
	 * lnet_notify_locked with different locks being held
	 */
	spin_lock(&gw->lpni_lock);

	if (pbuf->pb_info.pi_magic == __swab32(LNET_PROTO_PING_MAGIC))
		lnet_swap_pinginfo(pbuf);

	/* NB always racing with network! */
	if (pbuf->pb_info.pi_magic != LNET_PROTO_PING_MAGIC) {
		CDEBUG(D_NET, "%s: Unexpected magic %08x\n",
		       libcfs_nid2str(gw->lpni_nid), pbuf->pb_info.pi_magic);
		gw->lpni_ping_feats = LNET_PING_FEAT_INVAL;
		goto out;
	}

	gw->lpni_ping_feats = pbuf->pb_info.pi_features;

	/* Without NI status info there's nothing more to do. */
	if ((gw->lpni_ping_feats & LNET_PING_FEAT_NI_STATUS) == 0)
		goto out;

	/* Determine the number of NIs for which there is data. */
	nnis = pbuf->pb_info.pi_nnis;
	if (pbuf->pb_nnis < nnis) {
		if (rcd->rcd_nnis < nnis)
			rcd->rcd_nnis = nnis;
		nnis = pbuf->pb_nnis;
	}

	list_for_each_entry(rte, &gw->lpni_routes, lr_gwlist) {
		int	down = 0;
		int	up = 0;
		int	i;

		/* If routing disabled then the route is down. */
		if ((gw->lpni_ping_feats & LNET_PING_FEAT_RTE_DISABLED) != 0) {
			rte->lr_downis = 1;
			continue;
		}

		for (i = 0; i < nnis; i++) {
			struct lnet_ni_status *stat = &pbuf->pb_info.pi_ni[i];
			lnet_nid_t	 nid = stat->ns_nid;

			if (nid == LNET_NID_ANY) {
				CDEBUG(D_NET, "%s: unexpected LNET_NID_ANY\n",
				       libcfs_nid2str(gw->lpni_nid));
				gw->lpni_ping_feats = LNET_PING_FEAT_INVAL;
				goto out;
			}

			if (nid == LNET_NID_LO_0)
				continue;

			if (stat->ns_status == LNET_NI_STATUS_DOWN) {
				down++;
				continue;
			}

			if (stat->ns_status == LNET_NI_STATUS_UP) {
				if (LNET_NIDNET(nid) == rte->lr_net) {
					up = 1;
					break;
				}
				continue;
			}

			CDEBUG(D_NET, "%s: Unexpected status 0x%x\n",
			       libcfs_nid2str(gw->lpni_nid), stat->ns_status);
			gw->lpni_ping_feats = LNET_PING_FEAT_INVAL;
			goto out;
		}

		if (up) { /* ignore downed NIs if NI for dest network is up */
			rte->lr_downis = 0;
			continue;
		}
		/* if @down is zero and this route is single-hop, it means
		 * we can't find NI for target network */
		if (down == 0 && rte->lr_hops == 1)
			down = 1;

		rte->lr_downis = down;
	}
out:
	spin_unlock(&gw->lpni_lock);
}

static void
lnet_router_checker_event(struct lnet_event *event)
{
	struct lnet_rc_data *rcd = event->md.user_ptr;
	struct lnet_peer_ni *lp;

	LASSERT(rcd != NULL);

	if (event->unlinked) {
		LNetInvalidateMDHandle(&rcd->rcd_mdh);
		return;
	}

	LASSERT(event->type == LNET_EVENT_SEND ||
		event->type == LNET_EVENT_REPLY);

	lp = rcd->rcd_gateway;
	LASSERT(lp != NULL);

	 /* NB: it's called with holding lnet_res_lock, we have a few
	  * places need to hold both locks at the same time, please take
	  * care of lock ordering */
	lnet_net_lock(lp->lpni_cpt);
	if (!lnet_isrouter(lp) || lp->lpni_rcd != rcd) {
		/* ignore if no longer a router or rcd is replaced */
		goto out;
	}

	if (event->type == LNET_EVENT_SEND) {
		lp->lpni_ping_notsent = 0;
		if (event->status == 0)
			goto out;
	}

	/* LNET_EVENT_REPLY */
	/* A successful REPLY means the router is up.  If _any_ comms
	 * to the router fail I assume it's down (this will happen if
	 * we ping alive routers to try to detect router death before
	 * apps get burned). */

	lnet_notify_locked(lp, 1, !event->status, ktime_get_seconds());
	/* The router checker will wake up very shortly and do the
	 * actual notification.
	 * XXX If 'lp' stops being a router before then, it will still
	 * have the notification pending!!! */

	if (avoid_asym_router_failure && event->status == 0)
		lnet_parse_rc_info(rcd);

 out:
	lnet_net_unlock(lp->lpni_cpt);
}

static void
lnet_wait_known_routerstate(void)
{
	struct lnet_peer_ni *rtr;
	struct list_head *entry;
	int all_known;

	LASSERT(the_lnet.ln_mt_state == LNET_MT_STATE_RUNNING);

	/* the_lnet.ln_api_mutex must be locked */
	for (;;) {
		int cpt = lnet_net_lock_current();

		all_known = 1;
		list_for_each(entry, &the_lnet.ln_routers) {
			rtr = list_entry(entry, struct lnet_peer_ni,
					 lpni_rtr_list);

			spin_lock(&rtr->lpni_lock);

			if (rtr->lpni_alive_count == 0) {
				all_known = 0;
				spin_unlock(&rtr->lpni_lock);
				break;
			}
			spin_unlock(&rtr->lpni_lock);
		}

		lnet_net_unlock(cpt);

		if (all_known)
			return;

		mutex_unlock(&the_lnet.ln_api_mutex);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1));
		mutex_lock(&the_lnet.ln_api_mutex);
	}
}

void
lnet_router_ni_update_locked(struct lnet_peer_ni *gw, __u32 net)
{
	struct lnet_route *rte;

	if ((gw->lpni_ping_feats & LNET_PING_FEAT_NI_STATUS) != 0) {
		list_for_each_entry(rte, &gw->lpni_routes, lr_gwlist) {
			if (rte->lr_net == net) {
				rte->lr_downis = 0;
				break;
			}
		}
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

static void
lnet_destroy_rc_data(struct lnet_rc_data *rcd)
{
	LASSERT(list_empty(&rcd->rcd_list));
	/* detached from network */
	LASSERT(LNetMDHandleIsInvalid(rcd->rcd_mdh));

	if (rcd->rcd_gateway != NULL) {
		int cpt = rcd->rcd_gateway->lpni_cpt;

		lnet_net_lock(cpt);
		lnet_peer_ni_decref_locked(rcd->rcd_gateway);
		lnet_net_unlock(cpt);
	}

	if (rcd->rcd_pingbuffer != NULL)
		lnet_ping_buffer_decref(rcd->rcd_pingbuffer);

	LIBCFS_FREE(rcd, sizeof(*rcd));
}

static struct lnet_rc_data *
lnet_update_rc_data_locked(struct lnet_peer_ni *gateway)
{
	struct lnet_handle_md mdh;
	struct lnet_rc_data *rcd;
	struct lnet_ping_buffer *pbuf = NULL;
	int nnis = LNET_INTERFACES_MIN;
	int rc;
	int i;

	rcd = gateway->lpni_rcd;
	if (rcd) {
		nnis = rcd->rcd_nnis;
		mdh = rcd->rcd_mdh;
		LNetInvalidateMDHandle(&rcd->rcd_mdh);
		pbuf = rcd->rcd_pingbuffer;
		rcd->rcd_pingbuffer = NULL;
	} else {
		LNetInvalidateMDHandle(&mdh);
	}

	lnet_net_unlock(gateway->lpni_cpt);

	if (rcd) {
		LNetMDUnlink(mdh);
		lnet_ping_buffer_decref(pbuf);
	} else {
		LIBCFS_ALLOC(rcd, sizeof(*rcd));
		if (rcd == NULL)
			goto out;

		LNetInvalidateMDHandle(&rcd->rcd_mdh);
		INIT_LIST_HEAD(&rcd->rcd_list);
		rcd->rcd_nnis = nnis;
	}

	pbuf = lnet_ping_buffer_alloc(nnis, GFP_NOFS);
	if (pbuf == NULL)
		goto out;

	for (i = 0; i < nnis; i++) {
		pbuf->pb_info.pi_ni[i].ns_nid = LNET_NID_ANY;
		pbuf->pb_info.pi_ni[i].ns_status = LNET_NI_STATUS_INVALID;
	}
	rcd->rcd_pingbuffer = pbuf;

	LASSERT(!LNetEQHandleIsInvalid(the_lnet.ln_rc_eqh));
	rc = LNetMDBind((struct lnet_md){.start     = &pbuf->pb_info,
				    .user_ptr  = rcd,
				    .length    = LNET_PING_INFO_SIZE(nnis),
				    .threshold = LNET_MD_THRESH_INF,
				    .options   = LNET_MD_TRUNCATE,
				    .eq_handle = the_lnet.ln_rc_eqh},
			LNET_UNLINK,
			&rcd->rcd_mdh);
	if (rc < 0) {
		CERROR("Can't bind MD: %d\n", rc);
		goto out_ping_buffer_decref;
	}
	LASSERT(rc == 0);

	lnet_net_lock(gateway->lpni_cpt);
	/* Check if this is still a router. */
	if (!lnet_isrouter(gateway))
		goto out_unlock;
	/* Check if someone else installed router data. */
	if (gateway->lpni_rcd && gateway->lpni_rcd != rcd)
		goto out_unlock;

	/* Install and/or update the router data. */
	if (!gateway->lpni_rcd) {
		lnet_peer_ni_addref_locked(gateway);
		rcd->rcd_gateway = gateway;
		gateway->lpni_rcd = rcd;
	}
	gateway->lpni_ping_notsent = 0;

	return rcd;

out_unlock:
	lnet_net_unlock(gateway->lpni_cpt);
	rc = LNetMDUnlink(mdh);
	LASSERT(rc == 0);
out_ping_buffer_decref:
	lnet_ping_buffer_decref(pbuf);
out:
	if (rcd && rcd != gateway->lpni_rcd)
		lnet_destroy_rc_data(rcd);
	lnet_net_lock(gateway->lpni_cpt);
	return gateway->lpni_rcd;
}

static int
lnet_router_check_interval(struct lnet_peer_ni *rtr)
{
	int secs;

	secs = rtr->lpni_alive ? live_router_check_interval :
			       dead_router_check_interval;
	if (secs < 0)
		secs = 0;

	return secs;
}

static void
lnet_ping_router_locked(struct lnet_peer_ni *rtr)
{
	struct lnet_rc_data *rcd = NULL;
	time64_t now = ktime_get_seconds();
	time64_t secs;
	struct lnet_ni *ni;

	lnet_peer_ni_addref_locked(rtr);

	if (rtr->lpni_ping_deadline != 0 && /* ping timed out? */
	    now >  rtr->lpni_ping_deadline)
		lnet_notify_locked(rtr, 1, 0, now);

	/* Run any outstanding notifications */
	ni = lnet_get_next_ni_locked(rtr->lpni_net, NULL);
	lnet_ni_notify_locked(ni, rtr);

	if (!lnet_isrouter(rtr) ||
	    the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING) {
		/* router table changed or router checker is shutting down */
		lnet_peer_ni_decref_locked(rtr);
		return;
	}

	rcd = rtr->lpni_rcd;

	/*
	 * The response to the router checker ping could've timed out and
	 * the mdh might've been invalidated, so we need to update it
	 * again.
	 */
	if (!rcd || rcd->rcd_nnis > rcd->rcd_pingbuffer->pb_nnis ||
	    LNetMDHandleIsInvalid(rcd->rcd_mdh))
		rcd = lnet_update_rc_data_locked(rtr);
	if (rcd == NULL)
		return;

	secs = lnet_router_check_interval(rtr);

	CDEBUG(D_NET,
	       "rtr %s %lld: deadline %lld ping_notsent %d alive %d "
	       "alive_count %d lpni_ping_timestamp %lld\n",
	       libcfs_nid2str(rtr->lpni_nid), secs,
	       rtr->lpni_ping_deadline, rtr->lpni_ping_notsent,
	       rtr->lpni_alive, rtr->lpni_alive_count, rtr->lpni_ping_timestamp);

	if (secs != 0 && !rtr->lpni_ping_notsent &&
	    now > rtr->lpni_ping_timestamp + secs) {
		int               rc;
		struct lnet_process_id id;
		struct lnet_handle_md mdh;

		id.nid = rtr->lpni_nid;
		id.pid = LNET_PID_LUSTRE;
		CDEBUG(D_NET, "Check: %s\n", libcfs_id2str(id));

		rtr->lpni_ping_notsent   = 1;
		rtr->lpni_ping_timestamp = now;

		mdh = rcd->rcd_mdh;

		if (rtr->lpni_ping_deadline == 0) {
			rtr->lpni_ping_deadline = ktime_get_seconds() +
						  router_ping_timeout;
		}

		lnet_net_unlock(rtr->lpni_cpt);

		rc = LNetGet(LNET_NID_ANY, mdh, id, LNET_RESERVED_PORTAL,
			     LNET_PROTO_PING_MATCHBITS, 0, false);

		lnet_net_lock(rtr->lpni_cpt);
		if (rc != 0)
			rtr->lpni_ping_notsent = 0; /* no event pending */
	}

	lnet_peer_ni_decref_locked(rtr);
	return;
}

int lnet_router_pre_mt_start(void)
{
	int rc;

	if (check_routers_before_use &&
	    dead_router_check_interval <= 0) {
		LCONSOLE_ERROR_MSG(0x10a, "'dead_router_check_interval' must be"
				   " set if 'check_routers_before_use' is set"
				   "\n");
		return -EINVAL;
	}

	rc = LNetEQAlloc(0, lnet_router_checker_event, &the_lnet.ln_rc_eqh);
	if (rc != 0) {
		CERROR("Can't allocate EQ(0): %d\n", rc);
		return -ENOMEM;
	}

	return 0;
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

void
lnet_router_cleanup(void)
{
	int rc;

	rc = LNetEQFree(the_lnet.ln_rc_eqh);
	LASSERT(rc == 0);
	return;
}

void
lnet_prune_rc_data(int wait_unlink)
{
	struct lnet_rc_data *rcd;
	struct lnet_rc_data *tmp;
	struct lnet_peer_ni *lp;
	struct list_head head;
	int i = 2;

	if (likely(the_lnet.ln_mt_state == LNET_MT_STATE_RUNNING &&
		   list_empty(&the_lnet.ln_rcd_deathrow) &&
		   list_empty(&the_lnet.ln_rcd_zombie)))
		return;

	INIT_LIST_HEAD(&head);

	lnet_net_lock(LNET_LOCK_EX);

	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING) {
		/* router checker is stopping, prune all */
		list_for_each_entry(lp, &the_lnet.ln_routers,
				    lpni_rtr_list) {
			if (lp->lpni_rcd == NULL)
				continue;

			LASSERT(list_empty(&lp->lpni_rcd->rcd_list));
			list_add(&lp->lpni_rcd->rcd_list,
				 &the_lnet.ln_rcd_deathrow);
			lp->lpni_rcd = NULL;
		}
	}

	/* unlink all RCDs on deathrow list */
	list_splice_init(&the_lnet.ln_rcd_deathrow, &head);

	if (!list_empty(&head)) {
		lnet_net_unlock(LNET_LOCK_EX);

		list_for_each_entry(rcd, &head, rcd_list)
			LNetMDUnlink(rcd->rcd_mdh);

		lnet_net_lock(LNET_LOCK_EX);
	}

	list_splice_init(&head, &the_lnet.ln_rcd_zombie);

	/* release all zombie RCDs */
	while (!list_empty(&the_lnet.ln_rcd_zombie)) {
		list_for_each_entry_safe(rcd, tmp, &the_lnet.ln_rcd_zombie,
					 rcd_list) {
			if (LNetMDHandleIsInvalid(rcd->rcd_mdh))
				list_move(&rcd->rcd_list, &head);
		}

		wait_unlink = wait_unlink &&
			      !list_empty(&the_lnet.ln_rcd_zombie);

		lnet_net_unlock(LNET_LOCK_EX);

		while (!list_empty(&head)) {
			rcd = list_entry(head.next,
					 struct lnet_rc_data, rcd_list);
			list_del_init(&rcd->rcd_list);
			lnet_destroy_rc_data(rcd);
		}

		if (!wait_unlink)
			return;

		i++;
		CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
		       "Waiting for rc buffers to unlink\n");
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1) / 4);

		lnet_net_lock(LNET_LOCK_EX);
	}

	lnet_net_unlock(LNET_LOCK_EX);
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

	/* if there are routers that need to be cleaned up then do so */
	if (!list_empty(&the_lnet.ln_rcd_deathrow) ||
	    !list_empty(&the_lnet.ln_rcd_zombie))
		return true;

	return !list_empty(&the_lnet.ln_routers) &&
		(live_router_check_interval > 0 ||
		 dead_router_check_interval > 0);
}

void
lnet_check_routers(void)
{
	struct lnet_peer_ni *rtr;
	struct list_head *entry;
	__u64	version;
	int	cpt;
	int	cpt2;

	cpt = lnet_net_lock_current();
rescan:
	version = the_lnet.ln_routers_version;

	list_for_each(entry, &the_lnet.ln_routers) {
		rtr = list_entry(entry, struct lnet_peer_ni,
					lpni_rtr_list);

		cpt2 = rtr->lpni_cpt;
		if (cpt != cpt2) {
			lnet_net_unlock(cpt);
			cpt = cpt2;
			lnet_net_lock(cpt);
			/* the routers list has changed */
			if (version != the_lnet.ln_routers_version)
				goto rescan;
		}

		lnet_ping_router_locked(rtr);

		/* NB dropped lock */
		if (version != the_lnet.ln_routers_version) {
			/* the routers list has changed */
			goto rescan;
		}
	}

	if (the_lnet.ln_routing)
		lnet_update_ni_status_locked();

	lnet_net_unlock(cpt);

	lnet_prune_rc_data(0); /* don't wait for UNLINK */
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

int
lnet_notify(struct lnet_ni *ni, lnet_nid_t nid, int alive, time64_t when)
{
	struct lnet_peer_ni *lp = NULL;
	time64_t now = ktime_get_seconds();
	int cpt = lnet_cpt_of_nid(nid, ni);

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

	lnet_net_lock(cpt);

	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		lnet_net_unlock(cpt);
		return -ESHUTDOWN;
	}

	lp = lnet_find_peer_ni_locked(nid);
	if (lp == NULL) {
		/* nid not found */
		lnet_net_unlock(cpt);
		CDEBUG(D_NET, "%s not found\n", libcfs_nid2str(nid));
		return 0;
	}

	/*
	 * It is possible for this function to be called for the same peer
	 * but with different NIs. We want to synchronize the notification
	 * between the different calls. So we will use the lpni_cpt to
	 * grab the net lock.
	 */
	if (lp->lpni_cpt != cpt) {
		lnet_net_unlock(cpt);
		cpt = lp->lpni_cpt;
		lnet_net_lock(cpt);
	}

	/* We can't fully trust LND on reporting exact peer last_alive
	 * if he notifies us about dead peer. For example ksocklnd can
	 * call us with when == _time_when_the_node_was_booted_ if
	 * no connections were successfully established */
	if (ni != NULL && !alive && when < lp->lpni_last_alive)
		when = lp->lpni_last_alive;

	lnet_notify_locked(lp, ni == NULL, alive, when);

	if (ni != NULL)
		lnet_ni_notify_locked(ni, lp);

	lnet_peer_ni_decref_locked(lp);

	lnet_net_unlock(cpt);
	return 0;
}
EXPORT_SYMBOL(lnet_notify);
