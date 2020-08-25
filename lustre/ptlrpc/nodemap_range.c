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

#define START(node)	((node)->rn_start)
#define LAST(node)	((node)->rn_end)

INTERVAL_TREE_DEFINE(struct lu_nid_range, rn_rb, lnet_nid_t, rn_subtree_last,
		     START, LAST, static, nm_range)

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

	range->rn_start = start_nid;
	range->rn_end = end_nid;

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
	struct lu_nid_range *range;

	range = nm_range_iter_first(
		&nm_range_tree->nmrt_range_interval_root, start_nid, end_nid);
	while (range &&
	       (range->rn_start != start_nid || range->rn_end != end_nid))
		range = nm_range_iter_next(range, start_nid, end_nid);

	return range;
}

/*
 * range destructor
 */
void range_destroy(struct lu_nid_range *range)
{
	LASSERT(list_empty(&range->rn_list) == 0);

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
	if (nm_range_iter_first(&nm_range_tree->nmrt_range_interval_root,
				range->rn_start,
				range->rn_end))
		return -EEXIST;

	nm_range_insert(range, &nm_range_tree->nmrt_range_interval_root);

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
	list_del(&range->rn_list);
	nm_range_remove(range, &nm_range_tree->nmrt_range_interval_root);
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
	return nm_range_iter_first(
		&nm_range_tree->nmrt_range_interval_root, nid, nid);
}
