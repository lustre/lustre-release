/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (C) 2013, Trustees of Indiana University
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#include <lustre_net.h>
#include "nodemap_internal.h"
#include <linux/interval_tree_generic.h>

/*
 * Range trees
 *
 * To classify clients when they connect, build a global range tree
 * containing all admin defined ranges. Incoming clients can then be
 * classified into their nodemaps, and the lu_nodemap structure will be
 * set in the export structure for the connecting client. Pointers to
 * the lu_nid_range nodes will be added to linked links within the
 * lu_nodemap structure for reporting purposes. Access to range tree should be
 * controlled to prevent read access during update operations.
 */

#define START(node)	(lnet_nid_to_nid4(&((node)->rn_start)))
#define LAST(node)	(lnet_nid_to_nid4(&((node)->rn_end)))

INTERVAL_TREE_DEFINE(struct lu_nid_range, rn_rb, lnet_nid_t, rn_subtree_last,
		     START, LAST, static, nm_range)

/*
 * range constructor
 *
 * \param	config		nodemap config - used to set range id
 * \param	start_nid	starting nid of the range
 * \param	end_nid		ending nid of the range
 * \param	netmask		network mask prefix length
 * \param	nodemap		nodemap that contains this range
 * \param	range_id	should be 0 unless loading from disk
 * \retval	lu_nid_range on success, NULL on failure
 */
struct lu_nid_range *range_create(struct nodemap_config *config,
				  const struct lnet_nid *start_nid,
				  const struct lnet_nid *end_nid,
				  u8 netmask, struct lu_nodemap *nodemap,
				  unsigned int range_id)
{
	struct nodemap_range_tree *nm_range_tree;
	struct lu_nid_range *range;
	LIST_HEAD(tmp_nidlist);

	if (LNET_NID_NET(start_nid) != LNET_NID_NET(end_nid))
		return NULL;

	if (!netmask) {
		lnet_nid_t nid4[2] = {
			lnet_nid_to_nid4(start_nid),
			lnet_nid_to_nid4(end_nid)
		};

		if (LNET_NIDADDR(nid4[0]) > LNET_NIDADDR(nid4[1]))
			return NULL;
	} else if (!nid_same(start_nid, end_nid)) {
		/* A netmask is used with start_nid to form a nidmask. If the
		 * start_nid and end_nid differ then this indicates the
		 * specified range was malformed
		 */
		return NULL;
	}

	if (netmask) {
		/* +4 for '/<prefix_length>' */
		char nidstr[LNET_NIDSTR_SIZE + 4];
		char net[LNET_NIDSTR_SIZE];
		char *c;
		int rc;

		if (netmask > 128) {
			/* If the netmask is somehow more than three characters
			 * then the logic below could truncate it which could
			 * result in creating a valid netmask value from bad
			 * input.
			 * cfs_parse_nidlist() will check whether the netmask
			 * is valid for the address type
			 */
			CERROR("Invalid netmask %u\n", netmask);
			return NULL;
		}

		/* nidstr = <addr>@<net> */
		snprintf(nidstr, sizeof(nidstr), "%s",
			 libcfs_nidstr(start_nid));

		c = strchr(nidstr, '@');
		if (!c) {
			CERROR("Invalid nid %s for netmask\n",
			       libcfs_nidstr(start_nid));
			return NULL;
		}

		/* net = @<net> */
		strscpy(net, c, sizeof(net));

		*c = '\0';

		/* nidstr = <addr>/<prefix_length> */
		snprintf(c, sizeof(nidstr) - strlen(nidstr), "/%u", netmask);

		/* nidstr = <addr>/<prefix_length>@<net>
		 * (-1 to ensure room for null byte)
		 */
		strncat(nidstr, net, sizeof(nidstr) - strlen(nidstr) - 1);

		rc = cfs_parse_nidlist(nidstr, strlen(nidstr), &tmp_nidlist);
		if (rc) {
			CERROR("Invalid nidmask %s rc = %d\n", nidstr, rc);
			return NULL;
		}
	}

	OBD_ALLOC_PTR(range);
	if (range == NULL) {
		CERROR("cannot allocate lu_nid_range of size %zu bytes\n",
		       sizeof(*range));
		return NULL;
	}

	/* if we are loading from save, use on disk id num */
	nm_range_tree = &config->nmc_range_tree;
	if (range_id != 0) {
		if (nm_range_tree->nmrt_range_highest_id < range_id)
			nm_range_tree->nmrt_range_highest_id = range_id;
		range->rn_id = range_id;
	} else {
		nm_range_tree->nmrt_range_highest_id++;
		range->rn_id = nm_range_tree->nmrt_range_highest_id;
	}
	range->rn_nodemap = nodemap;

	range->rn_netmask = netmask;
	range->rn_start = *start_nid;
	range->rn_end = *end_nid;

	INIT_LIST_HEAD(&range->rn_list);
	INIT_LIST_HEAD(&range->rn_nidlist);
	if (!list_empty(&tmp_nidlist))
		list_splice(&tmp_nidlist, &range->rn_nidlist);

	return range;
}

/*
 * find the exact range
 *
 * \param	start_nid		starting nid
 * \param	end_nid			ending nid
 * \retval	matching range or NULL
 */
struct lu_nid_range *range_find(struct nodemap_config *config,
				const struct lnet_nid *start_nid,
				const struct lnet_nid *end_nid,
				u8 netmask)
{
	struct lu_nid_range *range = NULL;

	if (!netmask) {
		struct nodemap_range_tree *nm_range_tree;
		lnet_nid_t nid4[2];

		if (!nid_is_nid4(start_nid) || !nid_is_nid4(end_nid))
			return NULL;

		nid4[0] = lnet_nid_to_nid4(start_nid);
		nid4[1] = lnet_nid_to_nid4(end_nid);
		nm_range_tree = &config->nmc_range_tree;
		range = nm_range_iter_first(&nm_range_tree->nmrt_range_interval_root,
					    nid4[0], nid4[1]);
		while (range &&
		       (!nid_same(&range->rn_start, start_nid) ||
			!nid_same(&range->rn_end, end_nid)))
			range = nm_range_iter_next(range, nid4[0], nid4[1]);

		return range;
	}

	if (!list_empty(&config->nmc_netmask_setup)) {
		struct lu_nid_range *range_temp;
		u8 len;

		list_for_each_entry_safe(range, range_temp,
					 &config->nmc_netmask_setup,
					 rn_collect) {
			len = cfs_nidmask_get_length(&range->rn_nidlist);

			if (cfs_match_nid(start_nid, &range->rn_nidlist) &&
			    netmask == len)
				return range;
		}
	}

	return NULL;
}

/*
 * range destructor
 */
void range_destroy(struct lu_nid_range *range)
{
	LASSERT(list_empty(&range->rn_list) == 0);
	if (!list_empty(&range->rn_nidlist))
		cfs_free_nidlist(&range->rn_nidlist);

	OBD_FREE_PTR(range);
}

/*
 * insert an nid range into the interval tree
 *
 * \param	range		range to insert
 * \retval	0 on success
 *
 * This function checks that the given nid range
 * does not overlap so that each nid can belong
 * to exactly one range
 */
int range_insert(struct nodemap_config *config, struct lu_nid_range *range)
{
	if (!range->rn_netmask) {
		struct nodemap_range_tree *nm_range_tree;

		nm_range_tree = &config->nmc_range_tree;
		if (nm_range_iter_first(&nm_range_tree->nmrt_range_interval_root,
					lnet_nid_to_nid4(&range->rn_start),
					lnet_nid_to_nid4(&range->rn_end)))
			return -EEXIST;

		nm_range_insert(range,
				&nm_range_tree->nmrt_range_interval_root);
	} else {
		if (range_find(config, &range->rn_start, &range->rn_end,
			       range->rn_netmask))
			return -EEXIST;

		list_add(&range->rn_collect, &config->nmc_netmask_setup);
	}
	return 0;
}

/*
 * delete a range from the interval tree and any
 * associated nodemap references
 *
 * \param	range		range to remove
 */
void range_delete(struct nodemap_config *config, struct lu_nid_range *range)
{
	list_del(&range->rn_list);
	if (!range->rn_netmask) {
		struct nodemap_range_tree *nm_range_tree;

		nm_range_tree = &config->nmc_range_tree;
		nm_range_remove(range,
				&nm_range_tree->nmrt_range_interval_root);
	} else {
		list_del(&range->rn_collect);
	}
	range_destroy(range);
}

/*
 * search the interval tree for a nid within a range
 *
 * \param	nid		nid to search for
 */
struct lu_nid_range *range_search(struct nodemap_config *config,
				  struct lnet_nid *nid)
{
	if (nid_is_nid4(nid)) {
		struct nodemap_range_tree *nm_range_tree;

		nm_range_tree = &config->nmc_range_tree;
		return nm_range_iter_first(&nm_range_tree->nmrt_range_interval_root,
					   lnet_nid_to_nid4(nid),
					   lnet_nid_to_nid4(nid));
	}

	if (!list_empty(&config->nmc_netmask_setup)) {
		struct lu_nid_range *range, *range_temp;

		list_for_each_entry_safe(range, range_temp,
					 &config->nmc_netmask_setup,
					 rn_collect) {
			if (cfs_match_nid(nid, &range->rn_nidlist))
				return range;
		}
	}

	return NULL;
}
