/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * (visit-tags-table FILE)
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2007 Cluster File Systems, Inc.
 *   Author: Huang Wei <huangwei@clusterfs.com>
 *   Author: Jay Xiong <jinshan.xiong@sun.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef _INTERVAL_H__
#define _INTERVAL_H__

#include <libcfs/types.h>  /* __u8, __u64 etc. */
#include <libcfs/libcfs.h>   /* LASSERT. */

struct interval_node {
        struct interval_node   *in_left;
        struct interval_node   *in_right;
        struct interval_node   *in_parent;
        __u8                    in_color;
        __u8                    res1[7];  /* tags, 8-bytes aligned */
        __u64                   in_max_high;
        struct interval_node_extent {
                __u64 start;
                __u64 end;
        } in_extent;
};

enum interval_iter {
        INTERVAL_ITER_CONT = 1,
        INTERVAL_ITER_STOP = 2
};

static inline __u64 interval_low(struct interval_node *node)
{
        return node->in_extent.start;
}

static inline __u64 interval_high(struct interval_node *node)
{
        return node->in_extent.end;
}

static inline void interval_set(struct interval_node *node,
                                __u64 start, __u64 end)
{
        LASSERT(start <= end);
        node->in_extent.start = start;
        node->in_extent.end = end;
        node->in_max_high = end;
}

/* Rules to write an interval callback.
 *  - the callback returns INTERVAL_ITER_STOP when it thinks the iteration
 *    should be stopped. It will then cause the iteration function to return
 *    immediately with return value INTERVAL_ITER_STOP.
 *  - callbacks for interval_iterate and interval_iterate_reverse: Every 
 *    nodes in the tree will be set to @node before the callback being called
 *  - callback for interval_search: Only overlapped node will be set to @node
 *    before the callback being called.
 */
typedef enum interval_iter (*interval_callback_t)(struct interval_node *node,
                                                  void *args);

struct interval_node *interval_insert(struct interval_node *node,
                                      struct interval_node **root);
void interval_erase(struct interval_node *node, struct interval_node **root);

/* Search the extents in the tree and call @func for each overlapped
 * extents. */
enum interval_iter interval_search(struct interval_node *root,
                                   struct interval_node_extent *ex,
                                   interval_callback_t func, void *data);

/* Iterate every node in the tree - by reverse order or regular order. */
enum interval_iter interval_iterate(struct interval_node *root, 
                                    interval_callback_t func, void *data);
enum interval_iter interval_iterate_reverse(struct interval_node *root,
                                    interval_callback_t func,void *data);

void interval_expand(struct interval_node *root, 
                     struct interval_node_extent *ext,
                     struct interval_node_extent *limiter);
int interval_is_overlapped(struct interval_node *root, 
                           struct interval_node_extent *ex);
struct interval_node *interval_find(struct interval_node *root,
                                    struct interval_node_extent *ex);
#endif
