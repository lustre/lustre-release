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
#include <linux/rbtree.h>
#include "nodemap_internal.h"

/* This code is from a patch submitted by
 * Cody P Schafer <cody@linux.vnet.ibm.com> linux kernel
 * rbtree. When the supported kernel catches up to
 * the kernel where it is landed. To remove the
 * entire tree, it has to be done in postorder.
 *
 * I didn't write this other than to change the
 * function names to prevent collisions later.
 */

static struct rb_node *nm_rb_left_deepest_node(const struct rb_node *node);

static struct rb_node *nm_rb_left_deepest_node(const struct rb_node *node)
{
	while (true) {
		if (node->rb_left)
			node = node->rb_left;
		else if (node->rb_right)
			node = node->rb_right;
		else
			return (struct rb_node *) node;
	}
}

struct rb_node *nm_rb_next_postorder(const struct rb_node *node)
{
	const struct rb_node *parent;
	if (!node)
		return NULL;
	parent = rb_parent(node);

	if (parent && node == parent->rb_left && parent->rb_right)
		return nm_rb_left_deepest_node(parent->rb_right);
	else
		return (struct rb_node *) parent;
}

struct rb_node *nm_rb_first_postorder(const struct rb_root *root)
{
	if (!root->rb_node)
		return NULL;

	return nm_rb_left_deepest_node(root->rb_node);
}
