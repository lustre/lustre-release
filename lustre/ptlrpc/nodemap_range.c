// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
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
INTERVAL_TREE_DEFINE(struct lu_nid_range, rn_rb, lnet_nid_t, rn_subtree_last,
		     START, LAST, static, nm_range)

/**
 * range_create_generic() - Create a NID range
 * @nm_range_tree: range tree where to create range
 * @start_nid: starting nid of the range
 * @end_nid: ending nid of the range
 * @netmask: network mask prefix length
 * @nodemap: nodemap that contains this range
 * @range_id: should be 0 unless loading from disk
 *
 * Return:
 * * %range	range created
 * * %NULL	on failure
 */
static
struct lu_nid_range *range_create_generic(
	struct nodemap_range_tree *nm_range_tree,
	const struct lnet_nid *start_nid,
	const struct lnet_nid *end_nid,
	u8 netmask, struct lu_nodemap *nodemap,
	unsigned int range_id)
{
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
	range->rn_tree = NULL;
	range->rn_subtree.nmrt_range_interval_root = INTERVAL_TREE_ROOT;

	return range;
}

/**
 * range_create() - Create a regular NID range
 * @config: nodemap config to work on
 * @start_nid: starting nid of the range
 * @end_nid: ending nid of the range
 * @netmask: network mask prefix length
 * @nodemap: nodemap that contains this range
 * @range_id: should be 0 unless loading from disk
 *
 * Return:
 * * %range	range created
 * * %NULL	on failure
 */
struct lu_nid_range *range_create(struct nodemap_config *config,
				  const struct lnet_nid *start_nid,
				  const struct lnet_nid *end_nid,
				  u8 netmask, struct lu_nodemap *nodemap,
				  unsigned int range_id)
{
	return range_create_generic(&config->nmc_range_tree, start_nid, end_nid,
				    netmask, nodemap, range_id);
}

/**
 * ban_range_create() - Create a banned NID range
 * @config: nodemap config to work on
 * @start_nid: starting nid of the range
 * @end_nid: ending nid of the range
 * @netmask: network mask prefix length
 * @nodemap: nodemap that contains this range
 * @range_id: should be 0 unless loading from disk
 *
 * Return:
 * * %range	range created
 * * %NULL	on failure
 */
struct lu_nid_range *ban_range_create(struct nodemap_config *config,
				      const struct lnet_nid *start_nid,
				      const struct lnet_nid *end_nid,
				      u8 netmask, struct lu_nodemap *nodemap,
				      unsigned int range_id)
{
	return range_create_generic(&config->nmc_ban_range_tree, start_nid,
				    end_nid, netmask, nodemap, range_id);
}

static
struct lu_nid_range *__range_find(struct nodemap_range_tree *nm_range_tree,
				  const struct lnet_nid *start_nid,
				  const struct lnet_nid *end_nid,
				  bool exact)
{
	struct lu_nid_range *range, *found;
	lnet_nid_t nid4[2];

	if (!nid_is_nid4(start_nid) || !nid_is_nid4(end_nid))
		return NULL;

	nid4[0] = lnet_nid_to_nid4(start_nid);
	nid4[1] = lnet_nid_to_nid4(end_nid);

	range = nm_range_iter_first(&nm_range_tree->nmrt_range_interval_root,
				    nid4[0], nid4[1]);

	while (range) {
		if (__range_is_included(nid4[0], nid4[1], range)) {
			found = __range_find(&range->rn_subtree,
					     start_nid, end_nid, exact);
			if (found)
				return found;
			if (!exact)
				break;
		}
		if (exact &&
		    nid_same(&range->rn_start, start_nid) &&
		    nid_same(&range->rn_end, end_nid))
			break;
		range = nm_range_iter_next(range, nid4[0], nid4[1]);
	}

	return range;
}

/**
 * range_find_generic() - Find a NID range
 * @nm_range_tree: range tree where to find range
 * @netmask_setup: netmask where to find range
 * @start_nid: starting nid of the range
 * @end_nid: ending nid of the range
 * @netmask: network mask prefix length
 * @exact: true to get an exact match, false to get including range
 *
 * Return:
 * * %range	range found
 * * %NULL	on failure
 */
static struct lu_nid_range *range_find_generic(
	struct nodemap_range_tree *nm_range_tree,
	struct list_head *netmask_setup,
	const struct lnet_nid *start_nid,
	const struct lnet_nid *end_nid,
	u8 netmask, bool exact)
{
	struct lu_nid_range *range = NULL;

	if (!netmask) {
		return __range_find(nm_range_tree, start_nid, end_nid, exact);
	}

	if (!list_empty(netmask_setup)) {
		struct lu_nid_range *range_temp;
		u8 len;

		list_for_each_entry_safe(range, range_temp, netmask_setup,
					 rn_collect) {
			len = cfs_nidmask_get_length(&range->rn_nidlist);
			if (cfs_match_nid(start_nid, &range->rn_nidlist)) {
				if (exact) {
					if (netmask == len)
						return range;
				} else {
					/* Since cfs_match_nid() confirmed
					 * start_nid falls into the stored range
					 * we only need to verify the query is
					 * more specific.
					 */
					if (netmask >= len)
						return range;
				}
			}
		}
	}

	return NULL;
}

/**
 * range_find() - Find a regular NID range
 * @config: nodemap config to work on
 * @start_nid: starting nid of the range
 * @end_nid: ending nid of the range
 * @netmask: network mask prefix length
 * @exact: true to get an exact match, false to get including range
 *
 * Return:
 * * %range	range found
 * * %NULL	on failure
 */
struct lu_nid_range *range_find(struct nodemap_config *config,
				const struct lnet_nid *start_nid,
				const struct lnet_nid *end_nid,
				u8 netmask, bool exact)
{
	return range_find_generic(&config->nmc_range_tree,
				  &config->nmc_netmask_setup,
				  start_nid, end_nid, netmask, exact);
}

/**
 * ban_range_find() - Find an exact banned NID range
 * @config: nodemap config to work on
 * @start_nid: starting nid of the range
 * @end_nid: ending nid of the range
 * @netmask: network mask prefix length
 *
 * Return:
 * * %range	range found
 * * %NULL	on failure
 */
struct lu_nid_range *ban_range_find(struct nodemap_config *config,
				    const struct lnet_nid *start_nid,
				    const struct lnet_nid *end_nid,
				    u8 netmask)
{
	return range_find_generic(&config->nmc_ban_range_tree,
				  &config->nmc_ban_netmask_setup,
				  start_nid, end_nid, netmask, true);
}

/**
 * range_destroy() - Range destructor
 * @range: range to destroy
 */
void range_destroy(struct lu_nid_range *range)
{
	LASSERT(list_empty(&range->rn_list) == 0);
	if (!list_empty(&range->rn_nidlist))
		cfs_free_nidlist(&range->rn_nidlist);

	OBD_FREE_PTR(range);
}

static int __range_insert(struct nodemap_range_tree *nm_range_tree,
			  struct lu_nid_range *range,
			  struct lu_nid_range **parent_range, bool dynamic)
{
	struct lu_nid_range *found = NULL;
	int rc = 0;

	found = nm_range_iter_first(&nm_range_tree->nmrt_range_interval_root,
				    lnet_nid_to_nid4(&range->rn_start),
				    lnet_nid_to_nid4(&range->rn_end));
	if (found) {
		if (dynamic && range_is_included(range, found)) {
			rc = __range_insert(&found->rn_subtree,
					    range, parent_range, dynamic);
			if (!rc) {
				if (parent_range && !*parent_range)
					*parent_range = found;
			}
		} else {
			rc = -EEXIST;
		}
		GOTO(out_insert, rc);
	}

	nm_range_insert(range,
			&nm_range_tree->nmrt_range_interval_root);
	range->rn_tree = nm_range_tree;

out_insert:
	return rc;
}

/**
 * range_insert_generic() - Insert a nid range into the interval tree
 * @nm_range_tree: range tree where to insert range
 * @netmask_setup: netmask where to insert range
 * @range: range to insert
 * @parent_range: parent range
 * @dynamic: is dynamic nodemap
 *
 * This function checks that the given nid range
 * does not overlap so that each nid can belong
 * to exactly one range.
 *
 * Return:
 * * %0		success
 * * %-errno	on failure
 */
static int range_insert_generic(struct nodemap_range_tree *nm_range_tree,
				struct list_head *netmask_setup,
				struct lu_nid_range *range,
				struct lu_nid_range **parent_range,
				bool dynamic)
{
	int rc = 0;

	if (!range->rn_netmask) {
		rc = __range_insert(nm_range_tree, range, parent_range,
				    dynamic);
	} else {
		if (range_find_generic(nm_range_tree, netmask_setup,
				       &range->rn_start, &range->rn_end,
				       range->rn_netmask, true))
			return -EEXIST;

		list_add(&range->rn_collect, netmask_setup);
	}

	return rc;
}

/**
 * range_insert() - Insert a nid range into the regular interval tree
 * @config: nodemap config to work on
 * @range: range to insert
 * @parent_range: parent range
 * @dynamic: is dynamic nodemap
 *
 * This function checks that the given nid range
 * does not overlap so that each nid can belong
 * to exactly one range.
 *
 * Return:
 * * %0		success
 * * %-errno	on failure
 */
int range_insert(struct nodemap_config *config, struct lu_nid_range *range,
		 struct lu_nid_range **parent_range, bool dynamic)
{
	return range_insert_generic(&config->nmc_range_tree,
				    &config->nmc_netmask_setup,
				    range, parent_range, dynamic);
}

/**
 * ban_range_insert() - Insert a nid range into the banned interval tree
 * @config: nodemap config to work on
 * @range: range to insert
 * @parent_range: parent range
 * @dynamic: is dynamic nodemap
 *
 * This function checks that the given nid range
 * does not overlap so that each nid can belong
 * to exactly one range.
 *
 * Return:
 * * %0		success
 * * %-errno	on failure
 */
int ban_range_insert(struct nodemap_config *config, struct lu_nid_range *range,
		     struct lu_nid_range **parent_range, bool dynamic)
{
	return range_insert_generic(&config->nmc_ban_range_tree,
				    &config->nmc_ban_netmask_setup,
				    range, parent_range, dynamic);
}

/**
 * range_delete_generic() - Delete a range from the interval tree and any
 *			    associated nodemap references
 * @range: range to delete
 */
static void range_delete_generic(struct lu_nid_range *range)
{
	list_del(&range->rn_list);

	if (!range->rn_netmask) {
		if (range->rn_tree)
			nm_range_remove(range,
				    &range->rn_tree->nmrt_range_interval_root);
	} else {
		list_del(&range->rn_collect);
	}

	range_destroy(range);
}

/**
 * range_delete() - Delete a range from the regular interval tree and any
 *		    associated nodemap references
 * @config: nodemap config to work on
 * @range: range to delete
 */
void range_delete(struct nodemap_config *config, struct lu_nid_range *range)
{
	range_delete_generic(range);
}

/**
 * ban_range_delete() - Delete a range from the banned interval tree and any
 *			associated nodemap references
 * @config: nodemap config to work on
 * @range: range to delete
 */
void ban_range_delete(struct nodemap_config *config, struct lu_nid_range *range)
{
	range_delete_generic(range);
}

static
struct lu_nid_range *__range_search(struct nodemap_range_tree *nm_range_tree,
				    struct lnet_nid *nid)
{
	struct lu_nid_range *range, *subrange;

	range = nm_range_iter_first(&nm_range_tree->nmrt_range_interval_root,
				    lnet_nid_to_nid4(nid),
				    lnet_nid_to_nid4(nid));
	if (range) {
		subrange = __range_search(&range->rn_subtree, nid);
		if (subrange)
			range = subrange;
	}

	return range;
}

/**
 * range_search_generic() - Search interval tree for a nid within a range
 * @nm_range_tree: range tree to search
 * @netmask_setup: netmask to search
 * @nid: nid to search for
 *
 * Return:
 * * %range	range containing nid
 * * %NULL	on failure
 */
static struct lu_nid_range *range_search_generic(
	struct nodemap_range_tree *nm_range_tree,
	struct list_head *netmask_setup, struct lnet_nid *nid)
{
	if (nid_is_nid4(nid)) {
		return __range_search(nm_range_tree, nid);
	}

	if (!list_empty(netmask_setup)) {
		struct lu_nid_range *range, *range_temp;

		list_for_each_entry_safe(range, range_temp, netmask_setup,
					 rn_collect) {
			if (cfs_match_nid(nid, &range->rn_nidlist))
				return range;
		}
	}

	return NULL;
}

/**
 * range_search() - Search regular interval tree for a nid within a range
 * @config: nodemap config to work on
 * @nid: nid to search for
 *
 * Return:
 * * %range	range containing nid
 * * %NULL	on failure
 */
struct lu_nid_range *range_search(struct nodemap_config *config,
				  struct lnet_nid *nid)
{
	return range_search_generic(&config->nmc_range_tree,
				    &config->nmc_netmask_setup, nid);
}

/**
 * ban_range_search() - Search banned interval tree for a nid within a range
 * @config: nodemap config to work on
 * @nid: nid to search for
 *
 * Return:
 * * %range	range containing nid
 * * %NULL	on failure
 */
struct lu_nid_range *ban_range_search(struct nodemap_config *config,
				      struct lnet_nid *nid)
{
	return range_search_generic(&config->nmc_ban_range_tree,
				    &config->nmc_ban_netmask_setup, nid);
}
