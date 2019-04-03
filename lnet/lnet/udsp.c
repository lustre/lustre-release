/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2018-2020 Data Direct Networks.
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
 *   version 2 along with this program; If not, see
 *   http://www.gnu.org/licenses/gpl-2.0.html
 *
 *   lnet/lnet/udsp.c
 *
 *   User Defined Selection Policies (UDSP) are introduced to add
 *   ability of fine traffic control. The policies are instantiated
 *   on LNet constructs and allow preference of some constructs
 *   over others as an extension of the selection algorithm.
 *   The order of operation is defined by the selection algorithm logical flow:
 *
 *   1. Iterate over all the networks that a peer can be reached on
 *      and select the best local network
 *      - The remote network with the highest priority is examined
 *        (Network Rule)
 *      - The local network with the highest priority is selected
 *        (Network Rule)
 *      - The local NI with the highest priority is selected
 *        (NID Rule)
 *   2. If the peer is a remote peer and has no local networks,
 *      - then select the remote peer network with the highest priority
 *        (Network Rule)
 *      - Select the highest priority remote peer_ni on the network selected
 *        (NID Rule)
 *      - Now that the peer's network and NI are decided, select the router
 *        in round robin from the peer NI's preferred router list.
 *        (Router Rule)
 *      - Select the highest priority local NI on the local net of the
 *        selected route.
 *        (NID Rule)
 *   3. Otherwise for local peers, select the peer_ni from the peer.
 *      - highest priority peer NI is selected
 *        (NID Rule)
 *      - Select the peer NI which has the local NI selected on its
 *        preferred list.
 *        (NID Pair Rule)
 *
 *   Accordingly, the User Interface allows for the following:
 *   - Adding a local network udsp: if multiple local networks are
 *     available, each one can have a priority.
 *   - Adding a local NID udsp: after a local network is chosen,
 *     if there are multiple NIs, each one can have a priority.
 *   - Adding a remote NID udsp: assign priority to a peer NID.
 *   - Adding a NID pair udsp: allows to specify local NIDs
 *     to be added on the list on the specified peer NIs
 *     When selecting a peer NI, the one with the
 *     local NID being used on its list is preferred.
 *   - Adding a Router udsp: similar to the NID pair udsp.
 *     Specified router NIDs are added on the list on the specified peer NIs.
 *     When sending to a remote peer, remote net is selected and the peer NID
 *     is selected. The router which has its nid on the peer NI list
 *     is preferred.
 *   - Deleting a udsp: use the specified policy index to remove it
 *     from the policy list.
 *
 *   Generally, the syntax is as follows
 *     lnetctl policy <add | del | show>
 *      --src:      ip2nets syntax specifying the local NID to match
 *      --dst:      ip2nets syntax specifying the remote NID to match
 *      --rte:      ip2nets syntax specifying the router NID to match
 *      --priority: Priority to apply to rule matches
 *      --idx:      Index of where to insert or delete the rule
 *                  By default add appends to the end of the rule list
 *
 * Author: Amir Shehata
 */

#include <linux/uaccess.h>

#include <lnet/udsp.h>
#include <libcfs/libcfs.h>

struct udsp_info {
	struct lnet_peer_ni *udi_lpni;
	struct lnet_peer_net *udi_lpn;
	struct lnet_ni *udi_ni;
	struct lnet_net *udi_net;
	struct lnet_ud_nid_descr *udi_match;
	struct lnet_ud_nid_descr *udi_action;
	__u32 udi_priority;
	enum lnet_udsp_action_type udi_type;
	bool udi_local;
	bool udi_revert;
};

typedef int (*udsp_apply_rule)(struct udsp_info *);

enum udsp_apply {
	UDSP_APPLY_ON_PEERS = 0,
	UDSP_APPLY_PRIO_ON_NIS = 1,
	UDSP_APPLY_RTE_ON_NETS = 2,
	UDSP_APPLY_MAX_ENUM = 3,
};

#define RULE_NOT_APPLICABLE -1

static inline bool
lnet_udsp_is_net_rule(struct lnet_ud_nid_descr *match)
{
	return list_empty(&match->ud_addr_range);
}

static bool
lnet_udsp_expr_list_equal(struct list_head *e1,
			  struct list_head *e2)
{
	struct cfs_expr_list *expr1;
	struct cfs_expr_list *expr2;
	struct cfs_range_expr *range1, *range2;

	if (list_empty(e1) && list_empty(e2))
		return true;

	if (lnet_get_list_len(e1) != lnet_get_list_len(e2))
		return false;

	expr2 = list_first_entry(e2, struct cfs_expr_list, el_link);

	list_for_each_entry(expr1, e1, el_link) {
		if (lnet_get_list_len(&expr1->el_exprs) !=
		    lnet_get_list_len(&expr2->el_exprs))
			return false;

		range2 = list_first_entry(&expr2->el_exprs,
					  struct cfs_range_expr,
					  re_link);

		list_for_each_entry(range1, &expr1->el_exprs, re_link) {
			if (range1->re_lo != range2->re_lo ||
			    range1->re_hi != range2->re_hi ||
			    range1->re_stride != range2->re_stride)
				return false;
			range2 = list_next_entry(range2, re_link);
		}
		expr2 = list_next_entry(expr2, el_link);
	}

	return true;
}

static bool
lnet_udsp_nid_descr_equal(struct lnet_ud_nid_descr *e1,
			  struct lnet_ud_nid_descr *e2)
{
	if (e1->ud_net_id.udn_net_type != e2->ud_net_id.udn_net_type ||
	    !lnet_udsp_expr_list_equal(&e1->ud_net_id.udn_net_num_range,
				       &e2->ud_net_id.udn_net_num_range) ||
	    !lnet_udsp_expr_list_equal(&e1->ud_addr_range, &e2->ud_addr_range))
		return false;

	return true;
}

static bool
lnet_udsp_action_equal(struct lnet_udsp *e1, struct lnet_udsp *e2)
{
	if (e1->udsp_action_type != e2->udsp_action_type)
		return false;

	if (e1->udsp_action_type == EN_LNET_UDSP_ACTION_PRIORITY &&
	    e1->udsp_action.udsp_priority != e2->udsp_action.udsp_priority)
		return false;

	return true;
}

static bool
lnet_udsp_equal(struct lnet_udsp *e1, struct lnet_udsp *e2)
{
	/* check each NID descr */
	if (!lnet_udsp_nid_descr_equal(&e1->udsp_src, &e2->udsp_src) ||
	    !lnet_udsp_nid_descr_equal(&e1->udsp_dst, &e2->udsp_dst) ||
	    !lnet_udsp_nid_descr_equal(&e1->udsp_rte, &e2->udsp_rte))
		return false;

	return true;
}

/* it is enough to look at the net type of the descriptor. If the criteria
 * is present the net must be specified
 */
static inline bool
lnet_udsp_criteria_present(struct lnet_ud_nid_descr *descr)
{
	return (descr->ud_net_id.udn_net_type != 0);
}

static int
lnet_udsp_apply_rule_on_ni(struct udsp_info *udi)
{
	int rc;
	struct lnet_ni *ni = udi->udi_ni;
	struct lnet_ud_nid_descr *ni_match = udi->udi_match;
	__u32 priority = (udi->udi_revert) ? -1 : udi->udi_priority;

	rc = cfs_match_nid_net(ni->ni_nid,
		ni_match->ud_net_id.udn_net_type,
		&ni_match->ud_net_id.udn_net_num_range,
		&ni_match->ud_addr_range);
	if (!rc)
		return 0;

	CDEBUG(D_NET, "apply udsp on ni %s\n",
	       libcfs_nid2str(ni->ni_nid));

	/* Detected match. Set NIDs priority */
	lnet_ni_set_sel_priority_locked(ni, priority);

	return 0;
}

static int
lnet_udsp_apply_rte_list_on_net(struct lnet_net *net,
				struct lnet_ud_nid_descr *rte_action,
				bool revert)
{
	struct lnet_remotenet *rnet;
	struct list_head *rn_list;
	struct lnet_route *route;
	struct lnet_peer_ni *lpni;
	bool cleared = false;
	lnet_nid_t gw_nid, gw_prim_nid;
	int rc = 0;
	int i;

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++) {
		rn_list = &the_lnet.ln_remote_nets_hash[i];
		list_for_each_entry(rnet, rn_list, lrn_list) {
			list_for_each_entry(route, &rnet->lrn_routes, lr_list) {
				/* look if gw nid on the same net matches */
				gw_prim_nid = route->lr_gateway->lp_primary_nid;
				lpni = NULL;
				while ((lpni = lnet_get_next_peer_ni_locked(route->lr_gateway,
									    NULL,
									    lpni)) != NULL) {
					if (!lnet_get_net_locked(lpni->lpni_peer_net->lpn_net_id))
						continue;
					gw_nid = lpni->lpni_nid;
					rc = cfs_match_nid_net(gw_nid,
						rte_action->ud_net_id.udn_net_type,
						&rte_action->ud_net_id.udn_net_num_range,
						&rte_action->ud_addr_range);
					if (rc)
						break;
				}
				/* match gw primary nid on a remote network */
				if (!rc) {
					gw_nid = gw_prim_nid;
					rc = cfs_match_nid_net(gw_nid,
						rte_action->ud_net_id.udn_net_type,
						&rte_action->ud_net_id.udn_net_num_range,
						&rte_action->ud_addr_range);
				}
				if (!rc)
					continue;
				lnet_net_unlock(LNET_LOCK_EX);
				if (!cleared || revert) {
					lnet_net_clr_pref_rtrs(net);
					cleared = true;
					if (revert) {
						lnet_net_lock(LNET_LOCK_EX);
						continue;
					}
				}
				/* match. Add to pref NIDs */
				CDEBUG(D_NET, "udsp net->gw: %s->%s\n",
				       libcfs_net2str(net->net_id),
				       libcfs_nid2str(gw_prim_nid));
				rc = lnet_net_add_pref_rtr(net, gw_prim_nid);
				lnet_net_lock(LNET_LOCK_EX);
				/* success if EEXIST return */
				if (rc && rc != -EEXIST) {
					CERROR("Failed to add %s to %s pref rtr list\n",
					       libcfs_nid2str(gw_prim_nid),
					       libcfs_net2str(net->net_id));
					return rc;
				}
			}
		}
	}

	return rc;
}

static int
lnet_udsp_apply_rte_rule_on_nets(struct udsp_info *udi)
{
	int rc = 0;
	int last_failure = 0;
	struct lnet_net *net;
	struct lnet_ud_nid_descr *match = udi->udi_match;
	struct lnet_ud_nid_descr *rte_action = udi->udi_action;

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (LNET_NETTYP(net->net_id) != match->ud_net_id.udn_net_type)
			continue;

		rc = cfs_match_net(net->net_id,
				   match->ud_net_id.udn_net_type,
				   &match->ud_net_id.udn_net_num_range);
		if (!rc)
			continue;

		CDEBUG(D_NET, "apply rule on %s\n",
		       libcfs_net2str(net->net_id));
		rc = lnet_udsp_apply_rte_list_on_net(net, rte_action,
						     udi->udi_revert);
		if (rc)
			last_failure = rc;
	}

	return last_failure;
}

static int
lnet_udsp_apply_rte_rule_on_net(struct udsp_info *udi)
{
	int rc = 0;
	struct lnet_net *net = udi->udi_net;
	struct lnet_ud_nid_descr *match = udi->udi_match;
	struct lnet_ud_nid_descr *rte_action = udi->udi_action;

	rc = cfs_match_net(net->net_id,
			   match->ud_net_id.udn_net_type,
			   &match->ud_net_id.udn_net_num_range);
	if (!rc)
		return 0;

	CDEBUG(D_NET, "apply rule on %s\n",
		libcfs_net2str(net->net_id));
	rc = lnet_udsp_apply_rte_list_on_net(net, rte_action,
					     udi->udi_revert);

	return rc;
}

static int
lnet_udsp_apply_prio_rule_on_net(struct udsp_info *udi)
{
	int rc;
	struct lnet_ud_nid_descr *match = udi->udi_match;
	struct lnet_net *net = udi->udi_net;
	__u32 priority = (udi->udi_revert) ? -1 : udi->udi_priority;

	if (!lnet_udsp_is_net_rule(match))
		return RULE_NOT_APPLICABLE;

	rc = cfs_match_net(net->net_id,
			   match->ud_net_id.udn_net_type,
			   &match->ud_net_id.udn_net_num_range);
	if (!rc)
		return 0;

	CDEBUG(D_NET, "apply rule on %s\n",
	       libcfs_net2str(net->net_id));

	lnet_net_set_sel_priority_locked(net, priority);

	return 0;
}

static int
lnet_udsp_apply_rule_on_nis(struct udsp_info *udi)
{
	int rc = 0;
	struct lnet_ni *ni;
	struct lnet_net *net;
	struct lnet_ud_nid_descr *ni_match = udi->udi_match;
	int last_failure = 0;

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (LNET_NETTYP(net->net_id) != ni_match->ud_net_id.udn_net_type)
			continue;

		udi->udi_net = net;
		if (!lnet_udsp_apply_prio_rule_on_net(udi))
			continue;

		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			udi->udi_ni = ni;
			rc = lnet_udsp_apply_rule_on_ni(udi);
			if (rc)
				last_failure = rc;
		}
	}

	return last_failure;
}

static int
lnet_udsp_apply_rte_list_on_lpni(struct lnet_peer_ni *lpni,
				 struct lnet_ud_nid_descr *rte_action,
				 bool revert)
{
	struct lnet_remotenet *rnet;
	struct list_head *rn_list;
	struct lnet_route *route;
	bool cleared = false;
	lnet_nid_t gw_nid;
	int rc = 0;
	int i;

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++) {
		rn_list = &the_lnet.ln_remote_nets_hash[i];
		list_for_each_entry(rnet, rn_list, lrn_list) {
			list_for_each_entry(route, &rnet->lrn_routes, lr_list) {
				gw_nid = route->lr_gateway->lp_primary_nid;
				rc = cfs_match_nid_net(gw_nid,
					rte_action->ud_net_id.udn_net_type,
					&rte_action->ud_net_id.udn_net_num_range,
					&rte_action->ud_addr_range);
				if (!rc)
					continue;
				lnet_net_unlock(LNET_LOCK_EX);
				if (!cleared || revert) {
					CDEBUG(D_NET, "%spref rtr nids from lpni %s\n",
					       (revert) ? "revert " : "clear ",
					       libcfs_nid2str(lpni->lpni_nid));
					lnet_peer_clr_pref_rtrs(lpni);
					cleared = true;
					if (revert) {
						lnet_net_lock(LNET_LOCK_EX);
						continue;
					}
				}
				CDEBUG(D_NET, "add gw nid %s as preferred for peer %s\n",
				       libcfs_nid2str(gw_nid),
				       libcfs_nid2str(lpni->lpni_nid));
				/* match. Add to pref NIDs */
				rc = lnet_peer_add_pref_rtr(lpni, gw_nid);
				lnet_net_lock(LNET_LOCK_EX);
				/* success if EEXIST return */
				if (rc && rc != -EEXIST) {
					CERROR("Failed to add %s to %s pref rtr list\n",
					       libcfs_nid2str(gw_nid),
					       libcfs_nid2str(lpni->lpni_nid));
					return rc;
				}
			}
		}
	}

	return rc;
}

static int
lnet_udsp_apply_ni_list(struct lnet_peer_ni *lpni,
			struct lnet_ud_nid_descr *ni_action,
			bool revert)
{
	int rc = 0;
	struct lnet_ni *ni;
	struct lnet_net *net;
	bool cleared = false;

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (LNET_NETTYP(net->net_id) != ni_action->ud_net_id.udn_net_type)
			continue;
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			rc = cfs_match_nid_net(ni->ni_nid,
				ni_action->ud_net_id.udn_net_type,
				&ni_action->ud_net_id.udn_net_num_range,
				&ni_action->ud_addr_range);
			if (!rc)
				continue;
			lnet_net_unlock(LNET_LOCK_EX);
			if (!cleared || revert) {
				lnet_peer_clr_pref_nids(lpni);
				CDEBUG(D_NET, "%spref nids from lpni %s\n",
					(revert) ? "revert " : "clear ",
					libcfs_nid2str(lpni->lpni_nid));
				cleared = true;
				if (revert) {
					lnet_net_lock(LNET_LOCK_EX);
					continue;
				}
			}
			CDEBUG(D_NET, "add nid %s as preferred for peer %s\n",
				libcfs_nid2str(ni->ni_nid),
				libcfs_nid2str(lpni->lpni_nid));
			/* match. Add to pref NIDs */
			rc = lnet_peer_add_pref_nid(lpni, ni->ni_nid);
			lnet_net_lock(LNET_LOCK_EX);
			/* success if EEXIST return */
			if (rc && rc != -EEXIST) {
				CERROR("Failed to add %s to %s pref nid list\n",
					libcfs_nid2str(ni->ni_nid),
					libcfs_nid2str(lpni->lpni_nid));
				return rc;
			}
		}
	}

	return rc;
}

static int
lnet_udsp_apply_rule_on_lpni(struct udsp_info *udi)
{
	int rc;
	struct lnet_peer_ni *lpni = udi->udi_lpni;
	struct lnet_ud_nid_descr *lp_match = udi->udi_match;
	struct lnet_ud_nid_descr *action = udi->udi_action;
	__u32 priority = (udi->udi_revert) ? -1 : udi->udi_priority;
	bool local = udi->udi_local;
	enum lnet_udsp_action_type type = udi->udi_type;

	rc = cfs_match_nid_net(lpni->lpni_nid,
		lp_match->ud_net_id.udn_net_type,
		&lp_match->ud_net_id.udn_net_num_range,
		&lp_match->ud_addr_range);

	/* check if looking for a net match */
	if (!rc &&
	    (lnet_get_list_len(&lp_match->ud_addr_range) ||
	     !cfs_match_net(udi->udi_lpn->lpn_net_id,
			   lp_match->ud_net_id.udn_net_type,
			   &lp_match->ud_net_id.udn_net_num_range))) {
		return 0;
	}

	if (type == EN_LNET_UDSP_ACTION_PREFERRED_LIST && local) {
		rc = lnet_udsp_apply_ni_list(lpni, action,
					     udi->udi_revert);
		if (rc)
			return rc;
	} else if (type == EN_LNET_UDSP_ACTION_PREFERRED_LIST &&
			!local) {
		rc = lnet_udsp_apply_rte_list_on_lpni(lpni, action,
						      udi->udi_revert);
		if (rc)
			return rc;
	} else {
		lnet_peer_ni_set_selection_priority(lpni, priority);
	}

	return 0;
}

static int
lnet_udsp_apply_rule_on_lpn(struct udsp_info *udi)
{
	int rc;
	struct lnet_ud_nid_descr *match = udi->udi_match;
	struct lnet_peer_net *lpn = udi->udi_lpn;
	__u32 priority = (udi->udi_revert) ? -1 : udi->udi_priority;

	if (udi->udi_type == EN_LNET_UDSP_ACTION_PREFERRED_LIST ||
	    !lnet_udsp_is_net_rule(match))
		return RULE_NOT_APPLICABLE;

	rc = cfs_match_net(lpn->lpn_net_id,
			match->ud_net_id.udn_net_type,
			&match->ud_net_id.udn_net_num_range);
	if (!rc)
		return 0;

	CDEBUG(D_NET, "apply rule on lpn %s\n",
	       libcfs_net2str(lpn->lpn_net_id));
	lnet_peer_net_set_sel_priority_locked(lpn, priority);

	return 0;
}

static int
lnet_udsp_apply_rule_on_lpnis(struct udsp_info *udi)
{
	/* iterate over all the peers in the system and find if any of the
	 * peers match the criteria. If they do, clear the preferred list
	 * and add the new list
	 */
	int lncpt = cfs_percpt_number(the_lnet.ln_peer_tables);
	struct lnet_ud_nid_descr *lp_match = udi->udi_match;
	struct lnet_peer_table *ptable;
	struct lnet_peer_net *lpn;
	struct lnet_peer_ni *lpni;
	struct lnet_peer *lp;
	int last_failure = 0;
	int cpt;
	int rc;

	for (cpt = 0; cpt < lncpt; cpt++) {
		ptable = the_lnet.ln_peer_tables[cpt];
		list_for_each_entry(lp, &ptable->pt_peer_list, lp_peer_list) {
			CDEBUG(D_NET, "udsp examining lp %s\n",
			       libcfs_nid2str(lp->lp_primary_nid));
			list_for_each_entry(lpn,
					    &lp->lp_peer_nets,
					    lpn_peer_nets) {
				CDEBUG(D_NET, "udsp examining lpn %s\n",
				       libcfs_net2str(lpn->lpn_net_id));

				if (LNET_NETTYP(lpn->lpn_net_id) !=
				    lp_match->ud_net_id.udn_net_type)
					continue;

				udi->udi_lpn = lpn;

				if (!lnet_udsp_apply_rule_on_lpn(udi))
					continue;

				list_for_each_entry(lpni,
						    &lpn->lpn_peer_nis,
						    lpni_peer_nis) {
					CDEBUG(D_NET, "udsp examining lpni %s\n",
					       libcfs_nid2str(lpni->lpni_nid));
					udi->udi_lpni = lpni;
					rc = lnet_udsp_apply_rule_on_lpni(udi);
					if (rc)
						last_failure = rc;
				}
			}
		}
	}

	return last_failure;
}

static int
lnet_udsp_apply_single_policy(struct lnet_udsp *udsp, struct udsp_info *udi,
			      udsp_apply_rule *cbs)
{
	int rc;

	if (lnet_udsp_criteria_present(&udsp->udsp_dst) &&
	    lnet_udsp_criteria_present(&udsp->udsp_src)) {
		/* NID Pair rule */
		if (!cbs[UDSP_APPLY_ON_PEERS])
			return 0;

		if (udsp->udsp_action_type !=
			EN_LNET_UDSP_ACTION_PREFERRED_LIST) {
			CERROR("Bad action type. Expected %d got %d\n",
				EN_LNET_UDSP_ACTION_PREFERRED_LIST,
				udsp->udsp_action_type);
			return 0;
		}
		udi->udi_match = &udsp->udsp_dst;
		udi->udi_action = &udsp->udsp_src;
		udi->udi_type = EN_LNET_UDSP_ACTION_PREFERRED_LIST;
		udi->udi_local = true;

		CDEBUG(D_NET, "applying udsp (%p) dst->src\n",
			udsp);
		rc = cbs[UDSP_APPLY_ON_PEERS](udi);
		if (rc)
			return rc;
	} else if (lnet_udsp_criteria_present(&udsp->udsp_dst) &&
		   lnet_udsp_criteria_present(&udsp->udsp_rte)) {
		/* Router rule */
		if (!cbs[UDSP_APPLY_ON_PEERS])
			return 0;

		if (udsp->udsp_action_type !=
			EN_LNET_UDSP_ACTION_PREFERRED_LIST) {
			CERROR("Bad action type. Expected %d got %d\n",
				EN_LNET_UDSP_ACTION_PREFERRED_LIST,
				udsp->udsp_action_type);
			return 0;
		}

		if (lnet_udsp_criteria_present(&udsp->udsp_src)) {
			CERROR("only one of src or dst can be specified\n");
			return 0;
		}
		udi->udi_match = &udsp->udsp_dst;
		udi->udi_action = &udsp->udsp_rte;
		udi->udi_type = EN_LNET_UDSP_ACTION_PREFERRED_LIST;
		udi->udi_local = false;

		CDEBUG(D_NET, "applying udsp (%p) dst->rte\n",
			udsp);
		rc = cbs[UDSP_APPLY_ON_PEERS](udi);
		if (rc)
			return rc;
	} else if (lnet_udsp_criteria_present(&udsp->udsp_dst)) {
		/* destination priority rule */
		if (!cbs[UDSP_APPLY_ON_PEERS])
			return 0;

		if (udsp->udsp_action_type !=
			EN_LNET_UDSP_ACTION_PRIORITY) {
			CERROR("Bad action type. Expected %d got %d\n",
				EN_LNET_UDSP_ACTION_PRIORITY,
				udsp->udsp_action_type);
			return 0;
		}
		udi->udi_match = &udsp->udsp_dst;
		udi->udi_type = EN_LNET_UDSP_ACTION_PRIORITY;
		if (udsp->udsp_action_type !=
		    EN_LNET_UDSP_ACTION_PRIORITY) {
			udi->udi_priority = 0;
		} else {
			udi->udi_priority = udsp->udsp_action.udsp_priority;
		}
		udi->udi_local = true;

		CDEBUG(D_NET, "applying udsp (%p) on destination\n",
			udsp);
		rc = cbs[UDSP_APPLY_ON_PEERS](udi);
		if (rc)
			return rc;
	} else if (lnet_udsp_criteria_present(&udsp->udsp_src)) {
		/* source priority rule */
		if (!cbs[UDSP_APPLY_PRIO_ON_NIS])
			return 0;

		if (udsp->udsp_action_type !=
			EN_LNET_UDSP_ACTION_PRIORITY) {
			CERROR("Bad action type. Expected %d got %d\n",
				EN_LNET_UDSP_ACTION_PRIORITY,
				udsp->udsp_action_type);
			return 0;
		}
		udi->udi_match = &udsp->udsp_src;
		udi->udi_type = EN_LNET_UDSP_ACTION_PRIORITY;
		if (udsp->udsp_action_type !=
		    EN_LNET_UDSP_ACTION_PRIORITY) {
			udi->udi_priority = 0;
		} else {
			udi->udi_priority = udsp->udsp_action.udsp_priority;
		}
		udi->udi_local = true;

		CDEBUG(D_NET, "applying udsp (%p) on source\n",
			udsp);
		rc = cbs[UDSP_APPLY_PRIO_ON_NIS](udi);
	} else {
		CERROR("Bad UDSP policy\n");
		return 0;
	}

	return 0;
}

static int
lnet_udsp_apply_policies_helper(struct lnet_udsp *udsp, struct udsp_info *udi,
				udsp_apply_rule *cbs)
{
	int rc;
	int last_failure = 0;

	if (udsp)
		return lnet_udsp_apply_single_policy(udsp, udi, cbs);

	list_for_each_entry_reverse(udsp,
				    &the_lnet.ln_udsp_list,
				    udsp_on_list) {
		rc = lnet_udsp_apply_single_policy(udsp, udi, cbs);
		if (rc)
			last_failure = rc;
	}

	return last_failure;
}

int
lnet_udsp_apply_policies_on_ni(struct lnet_ni *ni)
{
	struct udsp_info udi;
	udsp_apply_rule cbs[UDSP_APPLY_MAX_ENUM] = {NULL};

	memset(&udi, 0, sizeof(udi));

	udi.udi_ni = ni;

	cbs[UDSP_APPLY_PRIO_ON_NIS] = lnet_udsp_apply_rule_on_ni;

	return lnet_udsp_apply_policies_helper(NULL, &udi, cbs);
}

int
lnet_udsp_apply_policies_on_net(struct lnet_net *net)
{
	struct udsp_info udi;
	udsp_apply_rule cbs[UDSP_APPLY_MAX_ENUM] = {NULL};

	memset(&udi, 0, sizeof(udi));

	udi.udi_net = net;

	cbs[UDSP_APPLY_PRIO_ON_NIS] = lnet_udsp_apply_prio_rule_on_net;
	cbs[UDSP_APPLY_RTE_ON_NETS] = lnet_udsp_apply_rte_rule_on_net;

	return lnet_udsp_apply_policies_helper(NULL, &udi, cbs);
}

int
lnet_udsp_apply_policies_on_lpni(struct lnet_peer_ni *lpni)
{
	struct udsp_info udi;
	udsp_apply_rule cbs[UDSP_APPLY_MAX_ENUM] = {NULL};

	memset(&udi, 0, sizeof(udi));

	udi.udi_lpni = lpni;

	cbs[UDSP_APPLY_ON_PEERS] = lnet_udsp_apply_rule_on_lpni;

	return lnet_udsp_apply_policies_helper(NULL, &udi, cbs);
}

int
lnet_udsp_apply_policies_on_lpn(struct lnet_peer_net *lpn)
{
	struct udsp_info udi;
	udsp_apply_rule cbs[UDSP_APPLY_MAX_ENUM] = {NULL};

	memset(&udi, 0, sizeof(udi));

	udi.udi_lpn = lpn;

	cbs[UDSP_APPLY_ON_PEERS] = lnet_udsp_apply_rule_on_lpn;

	return lnet_udsp_apply_policies_helper(NULL, &udi, cbs);
}

int
lnet_udsp_apply_policies(struct lnet_udsp *udsp, bool revert)
{
	int rc;
	struct udsp_info udi;
	udsp_apply_rule cbs[UDSP_APPLY_MAX_ENUM] = {NULL};

	memset(&udi, 0, sizeof(udi));

	cbs[UDSP_APPLY_ON_PEERS] = lnet_udsp_apply_rule_on_lpnis;
	cbs[UDSP_APPLY_PRIO_ON_NIS] = lnet_udsp_apply_rule_on_nis;
	cbs[UDSP_APPLY_RTE_ON_NETS] = lnet_udsp_apply_rte_rule_on_nets;

	udi.udi_revert = revert;

	lnet_net_lock(LNET_LOCK_EX);
	rc = lnet_udsp_apply_policies_helper(udsp, &udi, cbs);
	lnet_net_unlock(LNET_LOCK_EX);

	return rc;
}

struct lnet_udsp *
lnet_udsp_get_policy(int idx)
{
	int i = 0;
	struct lnet_udsp *udsp = NULL;
	bool found = false;

	CDEBUG(D_NET, "Get UDSP at idx = %d\n", idx);

	if (idx < 0)
		return NULL;

	list_for_each_entry(udsp, &the_lnet.ln_udsp_list, udsp_on_list) {
		CDEBUG(D_NET, "iterating over upsp %d:%d:%d\n",
		       udsp->udsp_idx, i, idx);
		if (i == idx) {
			found = true;
			break;
		}
		i++;
	}

	CDEBUG(D_NET, "Found UDSP (%p)\n", udsp);

	if (!found)
		return NULL;

	return udsp;
}

int
lnet_udsp_add_policy(struct lnet_udsp *new, int idx)
{
	struct lnet_udsp *udsp;
	struct lnet_udsp *insert = NULL;
	int i = 0;

	list_for_each_entry(udsp, &the_lnet.ln_udsp_list, udsp_on_list) {
		CDEBUG(D_NET, "found udsp i = %d:%d, idx = %d\n",
		       i, udsp->udsp_idx, idx);
		if (i == idx) {
			insert = udsp;
			new->udsp_idx = idx;
		}
		i++;
		if (lnet_udsp_equal(udsp, new)) {
			if (!lnet_udsp_action_equal(udsp, new) &&
			    udsp->udsp_action_type == EN_LNET_UDSP_ACTION_PRIORITY &&
			    new->udsp_action_type == EN_LNET_UDSP_ACTION_PRIORITY) {
				udsp->udsp_action.udsp_priority = new->udsp_action.udsp_priority;
				CDEBUG(D_NET, "udsp: %p index %d updated priority to %d\n",
				       udsp,
				       udsp->udsp_idx,
				       udsp->udsp_action.udsp_priority);
				return 0;
			}
			return -EALREADY;
		}
	}

	if (insert) {
		list_add(&new->udsp_on_list, insert->udsp_on_list.prev);
		i = 0;
		list_for_each_entry(udsp,
				    &the_lnet.ln_udsp_list,
				    udsp_on_list) {
			if (i <= idx) {
				i++;
				continue;
			}
			udsp->udsp_idx++;
		}
	} else {
		list_add_tail(&new->udsp_on_list, &the_lnet.ln_udsp_list);
		new->udsp_idx = i;
	}

	CDEBUG(D_NET, "udsp: %p added at index %d\n", new, new->udsp_idx);

	CDEBUG(D_NET, "udsp list:\n");
	list_for_each_entry(udsp, &the_lnet.ln_udsp_list, udsp_on_list)
		CDEBUG(D_NET, "udsp %p:%d\n", udsp, udsp->udsp_idx);

	return 0;
}

int
lnet_udsp_del_policy(int idx)
{
	struct lnet_udsp *udsp;
	struct lnet_udsp *tmp;
	bool removed = false;

	if (idx < 0) {
		lnet_udsp_destroy(false);
		return 0;
	}

	CDEBUG(D_NET, "del udsp at idx = %d\n", idx);

	list_for_each_entry_safe(udsp,
				 tmp,
				 &the_lnet.ln_udsp_list,
				 udsp_on_list) {
		if (removed)
			udsp->udsp_idx--;
		if (udsp->udsp_idx == idx && !removed) {
			list_del_init(&udsp->udsp_on_list);
			lnet_udsp_apply_policies(udsp, true);
			lnet_udsp_free(udsp);
			removed = true;
		}
	}

	return 0;
}

static void
lnet_udsp_get_ni_info(struct lnet_ioctl_construct_udsp_info *info,
		      struct lnet_ni *ni)
{
	struct lnet_nid_list *ne;
	struct lnet_net *net = ni->ni_net;
	int i = 0;

	LASSERT(ni);

	info->cud_nid_priority = ni->ni_sel_priority;
	if (net) {
		info->cud_net_priority = ni->ni_net->net_sel_priority;
		list_for_each_entry(ne, &net->net_rtr_pref_nids, nl_list) {
			if (i < LNET_MAX_SHOW_NUM_NID)
				info->cud_pref_rtr_nid[i] = ne->nl_nid;
			else
				break;
			i++;
		}
	}
}

static void
lnet_udsp_get_peer_info(struct lnet_ioctl_construct_udsp_info *info,
			struct lnet_peer_ni *lpni)
{
	struct lnet_nid_list *ne;
	int i = 0;

	/* peer tree structure needs to be in existence */
	LASSERT(lpni && lpni->lpni_peer_net &&
		lpni->lpni_peer_net->lpn_peer);

	info->cud_nid_priority = lpni->lpni_sel_priority;
	CDEBUG(D_NET, "lpni %s has %d pref nids\n",
	       libcfs_nid2str(lpni->lpni_nid),
	       lpni->lpni_pref_nnids);
	if (lpni->lpni_pref_nnids == 1) {
		info->cud_pref_nid[0] = lpni->lpni_pref.nid;
	} else if (lpni->lpni_pref_nnids > 1) {
		struct list_head *list = &lpni->lpni_pref.nids;

		list_for_each_entry(ne, list, nl_list) {
			if (i < LNET_MAX_SHOW_NUM_NID)
				info->cud_pref_nid[i] = ne->nl_nid;
			else
				break;
			i++;
		}
	}

	i = 0;
	list_for_each_entry(ne, &lpni->lpni_rtr_pref_nids, nl_list) {
		if (i < LNET_MAX_SHOW_NUM_NID)
			info->cud_pref_rtr_nid[i] = ne->nl_nid;
		else
			break;
		i++;
	}

	info->cud_net_priority = lpni->lpni_peer_net->lpn_sel_priority;
}

void
lnet_udsp_get_construct_info(struct lnet_ioctl_construct_udsp_info *info)
{
	struct lnet_ni *ni;
	struct lnet_peer_ni *lpni;

	lnet_net_lock(0);
	if (!info->cud_peer) {
		ni = lnet_nid2ni_locked(info->cud_nid, 0);
		if (ni)
			lnet_udsp_get_ni_info(info, ni);
	} else {
		lpni = lnet_find_peer_ni_locked(info->cud_nid);
		if (!lpni) {
			CDEBUG(D_NET, "nid %s is not found\n",
			       libcfs_nid2str(info->cud_nid));
		} else {
			lnet_udsp_get_peer_info(info, lpni);
			lnet_peer_ni_decref_locked(lpni);
		}
	}
	lnet_net_unlock(0);
}

struct lnet_udsp *
lnet_udsp_alloc(void)
{
	struct lnet_udsp *udsp;

	udsp = kmem_cache_alloc(lnet_udsp_cachep, GFP_NOFS | __GFP_ZERO);

	if (!udsp)
		return NULL;

	INIT_LIST_HEAD(&udsp->udsp_on_list);
	INIT_LIST_HEAD(&udsp->udsp_src.ud_addr_range);
	INIT_LIST_HEAD(&udsp->udsp_src.ud_net_id.udn_net_num_range);
	INIT_LIST_HEAD(&udsp->udsp_dst.ud_addr_range);
	INIT_LIST_HEAD(&udsp->udsp_dst.ud_net_id.udn_net_num_range);
	INIT_LIST_HEAD(&udsp->udsp_rte.ud_addr_range);
	INIT_LIST_HEAD(&udsp->udsp_rte.ud_net_id.udn_net_num_range);

	CDEBUG(D_MALLOC, "udsp alloc %p\n", udsp);
	return udsp;
}

static void
lnet_udsp_nid_descr_free(struct lnet_ud_nid_descr *nid_descr)
{
	struct list_head *net_range = &nid_descr->ud_net_id.udn_net_num_range;

	if (!lnet_udsp_criteria_present(nid_descr))
		return;

	/* memory management is a bit tricky here. When we allocate the
	 * memory to store the NID descriptor we allocate a large buffer
	 * for all the data, so we need to free the entire buffer at
	 * once. If the net is present the net_range->next points to that
	 * buffer otherwise if the ud_addr_range is present then it's the
	 * ud_addr_range.next
	 */
	if (!list_empty(net_range))
		LIBCFS_FREE(net_range->next, nid_descr->ud_mem_size);
	else if (!list_empty(&nid_descr->ud_addr_range))
		LIBCFS_FREE(nid_descr->ud_addr_range.next,
			    nid_descr->ud_mem_size);
}

void
lnet_udsp_free(struct lnet_udsp *udsp)
{
	lnet_udsp_nid_descr_free(&udsp->udsp_src);
	lnet_udsp_nid_descr_free(&udsp->udsp_dst);
	lnet_udsp_nid_descr_free(&udsp->udsp_rte);

	CDEBUG(D_MALLOC, "udsp free %p\n", udsp);
	kmem_cache_free(lnet_udsp_cachep, udsp);
}

void
lnet_udsp_destroy(bool shutdown)
{
	struct lnet_udsp *udsp, *tmp;

	CDEBUG(D_NET, "Destroying UDSPs in the system\n");

	list_for_each_entry_safe(udsp, tmp, &the_lnet.ln_udsp_list,
				 udsp_on_list) {
		list_del(&udsp->udsp_on_list);
		if (!shutdown)
			lnet_udsp_apply_policies(udsp, true);
		lnet_udsp_free(udsp);
	}
}

static size_t
lnet_size_marshaled_nid_descr(struct lnet_ud_nid_descr *descr)
{
	struct cfs_expr_list *expr;
	int expr_count = 0;
	int range_count = 0;
	size_t size = sizeof(struct lnet_ioctl_udsp_descr);

	if (!lnet_udsp_criteria_present(descr))
		return size;

	/* we always have one net expression */
	if (!list_empty(&descr->ud_net_id.udn_net_num_range)) {
		expr = list_first_entry(&descr->ud_net_id.udn_net_num_range,
					struct cfs_expr_list, el_link);

		/* count the number of cfs_range_expr in the net expression */
		range_count = lnet_get_list_len(&expr->el_exprs);
	}

	/* count the number of cfs_range_expr in the address expressions */
	list_for_each_entry(expr, &descr->ud_addr_range, el_link) {
		expr_count++;
		range_count += lnet_get_list_len(&expr->el_exprs);
	}

	size += (sizeof(struct lnet_expressions) * expr_count);
	size += (sizeof(struct lnet_range_expr) * range_count);

	return size;
}

size_t
lnet_get_udsp_size(struct lnet_udsp *udsp)
{
	size_t size = sizeof(struct lnet_ioctl_udsp);

	size += lnet_size_marshaled_nid_descr(&udsp->udsp_src);
	size += lnet_size_marshaled_nid_descr(&udsp->udsp_dst);
	size += lnet_size_marshaled_nid_descr(&udsp->udsp_rte);

	CDEBUG(D_NET, "get udsp (%p) size: %d\n", udsp, (int)size);

	return size;
}

static int
copy_exprs(struct cfs_expr_list *expr, void __user **bulk,
	   __u32 *bulk_size)
{
	struct cfs_range_expr *range;
	struct lnet_range_expr range_expr;

	/* copy over the net range expressions to the bulk */
	list_for_each_entry(range, &expr->el_exprs, re_link) {
		range_expr.re_lo = range->re_lo;
		range_expr.re_hi = range->re_hi;
		range_expr.re_stride = range->re_stride;
		CDEBUG(D_NET, "Copy Range %u:%u:%u\n",
		       range_expr.re_lo, range_expr.re_hi,
		       range_expr.re_stride);
		if (copy_to_user(*bulk, &range_expr, sizeof(range_expr))) {
			CDEBUG(D_NET, "Failed to copy range_expr\n");
			return -EFAULT;
		}
		*bulk += sizeof(range_expr);
		*bulk_size -= sizeof(range_expr);
	}

	return 0;
}

static int
copy_nid_range(struct lnet_ud_nid_descr *nid_descr, char *type,
		void __user **bulk, __u32 *bulk_size)
{
	struct lnet_ioctl_udsp_descr ioc_udsp_descr;
	struct cfs_expr_list *expr;
	struct lnet_expressions ioc_expr;
	int expr_count;
	int net_expr_count;
	int rc;

	memset(&ioc_udsp_descr, 0, sizeof(ioc_udsp_descr));
	ioc_udsp_descr.iud_src_hdr.ud_descr_type = *(__u32 *)type;

	/* if criteria not present, copy over the static part of the NID
	 * descriptor
	 */
	if (!lnet_udsp_criteria_present(nid_descr)) {
		CDEBUG(D_NET, "Descriptor %u:%u:%u:%u\n",
		       ioc_udsp_descr.iud_src_hdr.ud_descr_type,
		       ioc_udsp_descr.iud_src_hdr.ud_descr_count,
		       ioc_udsp_descr.iud_net.ud_net_type,
		       ioc_udsp_descr.iud_net.ud_net_num_expr.le_count);
		if (copy_to_user(*bulk, &ioc_udsp_descr,
				 sizeof(ioc_udsp_descr))) {
			CDEBUG(D_NET, "failed to copy ioc_udsp_descr\n");
			return -EFAULT;
		}
		*bulk += sizeof(ioc_udsp_descr);
		*bulk_size -= sizeof(ioc_udsp_descr);
		return 0;
	}

	expr_count = lnet_get_list_len(&nid_descr->ud_addr_range);

	/* copy the net information */
	if (!list_empty(&nid_descr->ud_net_id.udn_net_num_range)) {
		expr = list_first_entry(&nid_descr->ud_net_id.udn_net_num_range,
					struct cfs_expr_list, el_link);
		net_expr_count = lnet_get_list_len(&expr->el_exprs);
	} else {
		net_expr_count = 0;
	}

	/* set the total expression count */
	ioc_udsp_descr.iud_src_hdr.ud_descr_count = expr_count;
	ioc_udsp_descr.iud_net.ud_net_type =
		nid_descr->ud_net_id.udn_net_type;
	ioc_udsp_descr.iud_net.ud_net_num_expr.le_count = net_expr_count;

	CDEBUG(D_NET, "Descriptor %u:%u:%u:%u\n",
		ioc_udsp_descr.iud_src_hdr.ud_descr_type,
		ioc_udsp_descr.iud_src_hdr.ud_descr_count,
		ioc_udsp_descr.iud_net.ud_net_type,
		ioc_udsp_descr.iud_net.ud_net_num_expr.le_count);

	/* copy over the header info to the bulk */
	if (copy_to_user(*bulk, &ioc_udsp_descr, sizeof(ioc_udsp_descr))) {
		CDEBUG(D_NET, "Failed to copy data\n");
		return -EFAULT;
	}
	*bulk += sizeof(ioc_udsp_descr);
	*bulk_size -= sizeof(ioc_udsp_descr);

	/* copy over the net num expression if it exists */
	if (net_expr_count) {
		rc = copy_exprs(expr, bulk, bulk_size);
		if (rc)
			return rc;
	}

	/* copy the address range */
	list_for_each_entry(expr, &nid_descr->ud_addr_range, el_link) {
		ioc_expr.le_count = lnet_get_list_len(&expr->el_exprs);
		if (copy_to_user(*bulk, &ioc_expr, sizeof(ioc_expr))) {
			CDEBUG(D_NET, "failex to copy ioc_expr\n");
			return -EFAULT;
		}
		*bulk += sizeof(ioc_expr);
		*bulk_size -= sizeof(ioc_expr);

		rc = copy_exprs(expr, bulk, bulk_size);
		if (rc)
			return rc;
	}

	return 0;
}

int
lnet_udsp_marshal(struct lnet_udsp *udsp, struct lnet_ioctl_udsp *ioc_udsp)
{
	int rc = -ENOMEM;
	void __user *bulk;
	__u32 bulk_size;

	if (!ioc_udsp)
		return -EINVAL;

	bulk = ioc_udsp->iou_bulk;
	bulk_size = ioc_udsp->iou_hdr.ioc_len +
	  ioc_udsp->iou_bulk_size;

	CDEBUG(D_NET, "marshal udsp (%p)\n", udsp);
	CDEBUG(D_NET, "MEM -----> bulk: %p:0x%x\n", bulk, bulk_size);
	/* make sure user space allocated enough buffer to marshal the
	 * udsp
	 */
	if (bulk_size != lnet_get_udsp_size(udsp)) {
		rc = -ENOSPC;
		goto fail;
	}

	ioc_udsp->iou_idx = udsp->udsp_idx;
	ioc_udsp->iou_action_type = udsp->udsp_action_type;
	ioc_udsp->iou_action.priority = udsp->udsp_action.udsp_priority;

	bulk_size -= sizeof(*ioc_udsp);

	rc = copy_nid_range(&udsp->udsp_src, "SRC", &bulk, &bulk_size);
	if (rc)
		goto fail;

	rc = copy_nid_range(&udsp->udsp_dst, "DST", &bulk, &bulk_size);
	if (rc)
		goto fail;

	rc = copy_nid_range(&udsp->udsp_rte, "RTE", &bulk, &bulk_size);
	if (rc)
		goto fail;

	CDEBUG(D_NET, "MEM <----- bulk: %p\n", bulk);

	/* we should've consumed the entire buffer */
	LASSERT(bulk_size == 0);
	return 0;

fail:
	CERROR("Failed to marshal udsp: %d\n", rc);
	return rc;
}

static void
copy_range_info(void **bulk, void **buf, struct list_head *list,
		int count)
{
	struct lnet_range_expr *range_expr;
	struct cfs_range_expr *range;
	struct cfs_expr_list *exprs;
	int range_count = count;
	int i;

	if (range_count == 0)
		return;

	if (range_count == -1) {
		struct lnet_expressions *e;

		e = *bulk;
		range_count = e->le_count;
		*bulk += sizeof(*e);
	}

	exprs = *buf;
	INIT_LIST_HEAD(&exprs->el_link);
	INIT_LIST_HEAD(&exprs->el_exprs);
	list_add_tail(&exprs->el_link, list);
	*buf += sizeof(*exprs);

	for (i = 0; i < range_count; i++) {
		range_expr = *bulk;
		range = *buf;
		INIT_LIST_HEAD(&range->re_link);
		range->re_lo = range_expr->re_lo;
		range->re_hi = range_expr->re_hi;
		range->re_stride = range_expr->re_stride;
		CDEBUG(D_NET, "Copy Range %u:%u:%u\n",
		       range->re_lo,
		       range->re_hi,
		       range->re_stride);
		list_add_tail(&range->re_link, &exprs->el_exprs);
		*bulk += sizeof(*range_expr);
		*buf += sizeof(*range);
	}
}

static int
copy_ioc_udsp_descr(struct lnet_ud_nid_descr *nid_descr, char *type,
		    void **bulk, __u32 *bulk_size)
{
	struct lnet_ioctl_udsp_descr *ioc_nid = *bulk;
	struct lnet_expressions *exprs;
	__u32 descr_type;
	int expr_count = 0;
	int range_count = 0;
	int i;
	__u32 size;
	int remaining_size = *bulk_size;
	void *tmp = *bulk;
	__u32 alloc_size;
	void *buf;
	size_t range_expr_s = sizeof(struct lnet_range_expr);
	size_t lnet_exprs_s = sizeof(struct lnet_expressions);

	CDEBUG(D_NET, "%s: bulk = %p:%u\n", type, *bulk, *bulk_size);

	/* criteria not present, skip over the static part of the
	 * bulk, which is included for each NID descriptor
	 */
	if (ioc_nid->iud_net.ud_net_type == 0) {
		remaining_size -= sizeof(*ioc_nid);
		if (remaining_size < 0) {
			CERROR("Truncated userspace udsp buffer given\n");
			return -EINVAL;
		}
		*bulk += sizeof(*ioc_nid);
		*bulk_size = remaining_size;
		return 0;
	}

	descr_type = ioc_nid->iud_src_hdr.ud_descr_type;
	if (descr_type != *(__u32 *)type) {
		CERROR("Bad NID descriptor type. Expected %s, given %c%c%c\n",
			type, (__u8)descr_type, (__u8)(descr_type << 4),
			(__u8)(descr_type << 8));
		return -EINVAL;
	}

	/* calculate the total size to verify we have enough buffer.
	 * Start of by finding how many ranges there are for the net
	 * expression.
	 */
	range_count = ioc_nid->iud_net.ud_net_num_expr.le_count;
	size = sizeof(*ioc_nid) + (range_count * range_expr_s);
	remaining_size -= size;
	if (remaining_size < 0) {
		CERROR("Truncated userspace udsp buffer given\n");
		return -EINVAL;
	}

	CDEBUG(D_NET, "Total net num ranges in %s: %d:%u\n", type,
	       range_count, size);
	/* the number of expressions for the NID. IE 4 for IP, 1 for GNI */
	expr_count = ioc_nid->iud_src_hdr.ud_descr_count;
	CDEBUG(D_NET, "addr as %d exprs\n", expr_count);
	/* point tmp to the beginning of the NID expressions */
	tmp += size;
	for (i = 0; i < expr_count; i++) {
		/* get the number of ranges per expression */
		exprs = tmp;
		range_count += exprs->le_count;
		size = (range_expr_s * exprs->le_count) + lnet_exprs_s;
		remaining_size -= size;
		CDEBUG(D_NET, "expr %d:%d:%u:%d:%d\n", i, exprs->le_count,
		       size, remaining_size, range_count);
		if (remaining_size < 0) {
			CERROR("Truncated userspace udsp buffer given\n");
			return -EINVAL;
		}
		tmp += size;
	}

	*bulk_size = remaining_size;

	/* copy over the net type */
	nid_descr->ud_net_id.udn_net_type = ioc_nid->iud_net.ud_net_type;

	CDEBUG(D_NET, "%u\n", nid_descr->ud_net_id.udn_net_type);

	/* allocate the total memory required to copy this NID descriptor */
	alloc_size = (sizeof(struct cfs_expr_list) * (expr_count + 1)) +
		     (sizeof(struct cfs_range_expr) * (range_count));
	LIBCFS_ALLOC(buf, alloc_size);
	if (!buf)
		return -ENOMEM;

	/* store the amount of memory allocated so we can free it later on */
	nid_descr->ud_mem_size = alloc_size;

	/* copy over the net number range */
	range_count = ioc_nid->iud_net.ud_net_num_expr.le_count;
	*bulk += sizeof(*ioc_nid);
	CDEBUG(D_NET, "bulk = %p\n", *bulk);
	copy_range_info(bulk, &buf, &nid_descr->ud_net_id.udn_net_num_range,
			range_count);
	CDEBUG(D_NET, "bulk = %p\n", *bulk);

	/* copy over the NID descriptor */
	for (i = 0; i < expr_count; i++) {
		copy_range_info(bulk, &buf, &nid_descr->ud_addr_range, -1);
		CDEBUG(D_NET, "bulk = %p\n", *bulk);
	}

	return 0;
}

int
lnet_udsp_demarshal_add(void *bulk, __u32 bulk_size)
{
	struct lnet_ioctl_udsp *ioc_udsp;
	struct lnet_udsp *udsp;
	int rc = -ENOMEM;
	int idx;

	if (bulk_size < sizeof(*ioc_udsp))
		return -ENOSPC;

	udsp = lnet_udsp_alloc();
	if (!udsp)
		return rc;

	ioc_udsp = bulk;

	udsp->udsp_action_type = ioc_udsp->iou_action_type;
	udsp->udsp_action.udsp_priority = ioc_udsp->iou_action.priority;
	idx = ioc_udsp->iou_idx;

	CDEBUG(D_NET, "demarshal descr %u:%u:%d:%u\n", udsp->udsp_action_type,
	       udsp->udsp_action.udsp_priority, idx, bulk_size);

	bulk += sizeof(*ioc_udsp);
	bulk_size -= sizeof(*ioc_udsp);

	rc = copy_ioc_udsp_descr(&udsp->udsp_src, "SRC", &bulk, &bulk_size);
	if (rc < 0)
		goto free_udsp;

	rc = copy_ioc_udsp_descr(&udsp->udsp_dst, "DST", &bulk, &bulk_size);
	if (rc < 0)
		goto free_udsp;

	rc = copy_ioc_udsp_descr(&udsp->udsp_rte, "RTE", &bulk, &bulk_size);
	if (rc < 0)
		goto free_udsp;

	return lnet_udsp_add_policy(udsp, idx);

free_udsp:
	lnet_udsp_free(udsp);
	return rc;
}
