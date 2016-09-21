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

#include <interval_tree.h>
#include <lustre_net.h>
#include "nodemap_internal.h"

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

/*
 * callback for iterating over the interval tree
 *
 * \param	n		interval_node matched
 * \param	data		void pointer for return
 *
 * This function stops after a single match. There should be
 * no intervals containing multiple ranges
 */
static enum interval_iter range_cb(struct interval_node *n, void *data)
{
	struct lu_nid_range	*range = container_of(n, struct lu_nid_range,
						      rn_node);
	struct lu_nid_range	**ret;

	ret = data;
	*ret = range;

	return INTERVAL_ITER_STOP;
}

/*
 * range constructor
 *
 * \param	min		starting nid of the range
 * \param	max		ending nid of the range
 * \param	nodemap		nodemap that contains this range
 * \retval	lu_nid_range on success, NULL on failure
 */
struct lu_nid_range *range_create(struct nodemap_range_tree *nm_range_tree,
				  lnet_nid_t start_nid, lnet_nid_t end_nid,
				  struct lu_nodemap *nodemap, unsigned range_id)
{
	struct lu_nid_range *range;
	int rc;

	if (LNET_NIDNET(start_nid) != LNET_NIDNET(end_nid) ||
	    LNET_NIDADDR(start_nid) > LNET_NIDADDR(end_nid))
		return NULL;

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

	rc = interval_set(&range->rn_node, start_nid, end_nid);
	if (rc < 0) {
		OBD_FREE_PTR(range);
		return NULL;
	}

	INIT_LIST_HEAD(&range->rn_list);

	return range;
}

/*
 * find the exact range
 *
 * \param	start_nid		starting nid
 * \param	end_nid			ending nid
 * \retval	matching range or NULL
 */
struct lu_nid_range *range_find(struct nodemap_range_tree *nm_range_tree,
				lnet_nid_t start_nid, lnet_nid_t end_nid)
{
	struct lu_nid_range		*range = NULL;
	struct interval_node		*interval = NULL;
	struct interval_node_extent	ext = {
		.start	= start_nid,
		.end	= end_nid
	};

	interval = interval_find(nm_range_tree->nmrt_range_interval_root, &ext);

	if (interval != NULL)
		range = container_of(interval, struct lu_nid_range,
				     rn_node);

	return range;
}

/*
 * range destructor
 */
void range_destroy(struct lu_nid_range *range)
{
	LASSERT(list_empty(&range->rn_list) == 0);
	LASSERT(interval_is_intree(&range->rn_node) == 0);

	OBD_FREE_PTR(range);
}

/*
 * insert an nid range into the interval tree
 *
 * \param	range		range to insetr
 * \retval	0 on success
 *
 * This function checks that the given nid range
 * does not overlap so that each nid can belong
 * to exactly one range
 */
int range_insert(struct nodemap_range_tree *nm_range_tree,
		 struct lu_nid_range *range)
{
	struct interval_node_extent ext =
			range->rn_node.in_extent;

	if (interval_is_overlapped(nm_range_tree->nmrt_range_interval_root,
				   &ext) != 0)
		return -EEXIST;

	interval_insert(&range->rn_node,
			&nm_range_tree->nmrt_range_interval_root);

	return 0;
}

/*
 * delete a range from the interval tree and any
 * associated nodemap references
 *
 * \param	range		range to remove
 */
void range_delete(struct nodemap_range_tree *nm_range_tree,
		  struct lu_nid_range *range)
{
	if (range == NULL || interval_is_intree(&range->rn_node) == 0)
		return;
	list_del(&range->rn_list);
	interval_erase(&range->rn_node,
		       &nm_range_tree->nmrt_range_interval_root);
	range_destroy(range);
}

/*
 * search the interval tree for an nid within a range
 *
 * \param	nid		nid to search for
 */
struct lu_nid_range *range_search(struct nodemap_range_tree *nm_range_tree,
				  lnet_nid_t nid)
{
	struct lu_nid_range		*ret = NULL;
	struct interval_node_extent	ext = {
		.start	= nid,
		.end	= nid
	};

	interval_search(nm_range_tree->nmrt_range_interval_root, &ext,
			range_cb, &ret);

	return ret;
}
