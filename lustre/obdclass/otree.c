/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Copyright (C) 2002, 2003  Cluster File Systems, Inc
 *
 *  our offset trees (otrees) track single-bit state of offsets in an
 *  extent tree.  
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#include <linux/version.h>
#include <linux/config.h>
#include <linux/module.h>

#define DEBUG_SUBSYSTEM S_OSC
#include <linux/kp30.h>
#include <linux/obd.h>
#include <linux/lustre_debug.h>
#include <linux/lustre_otree.h>

struct offset_extent {
        rb_node_t       oe_node;
        unsigned long   oe_start, oe_end;
};

static struct offset_extent * ot_find_oe(rb_root_t *root,
                                         struct offset_extent *needle)
{
        struct rb_node_s *node = root->rb_node;
        struct offset_extent *oe;
        ENTRY;

        CDEBUG(D_INODE, "searching [%lu -> %lu]\n", needle->oe_start,
               needle->oe_end);

        while (node) {
                oe = rb_entry(node, struct offset_extent, oe_node);
                if (needle->oe_end < oe->oe_start)
                        node = node->rb_left;
                else if (needle->oe_start > oe->oe_end)
                        node = node->rb_right;
                else {
                        CDEBUG(D_INODE, "returning [%lu -> %lu]\n",
                               oe->oe_start, oe->oe_end);
                        RETURN(oe);
                }
        }
        RETURN(NULL);
}

/* do the rbtree mechanics to insert a node, callers are responsible
 * for making sure that this new node doesn't overlap with existing
 * nodes */
static void ot_insert_oe(rb_root_t *root, struct offset_extent *new_oe)
{
        rb_node_t ** p = &root->rb_node;
        rb_node_t * parent = NULL;
        struct offset_extent *oe;
        ENTRY;

        LASSERT(new_oe->oe_start <= new_oe->oe_end);

        while (*p) {
                parent = *p;
                oe = rb_entry(parent, struct offset_extent, oe_node);
                if ( new_oe->oe_end < oe->oe_start )
                        p = &(*p)->rb_left;
                else if ( new_oe->oe_start > oe->oe_end )
                        p = &(*p)->rb_right;
                else
                        LBUG();
        }
        rb_link_node(&new_oe->oe_node, parent, p);
        rb_insert_color(&new_oe->oe_node, root);
        EXIT;
}

int ot_mark_offset(struct otree *ot, unsigned long offset)
{
        struct offset_extent needle, *oe, *new_oe;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(new_oe, sizeof(*new_oe));
        if (new_oe == NULL)
                RETURN(-ENOMEM);

        spin_lock(&ot->ot_lock);

        /* find neighbours that we might glom on to */
        needle.oe_start = (offset > 0) ? offset - 1 : offset;
        needle.oe_end = (offset < ~0) ? offset + 1 : offset;
        oe = ot_find_oe(&ot->ot_root, &needle);
        if ( oe == NULL ) {
                new_oe->oe_start = offset;
                new_oe->oe_end = offset;
                ot_insert_oe(&ot->ot_root, new_oe);
                ot->ot_num_marked++;
                new_oe = NULL;
                GOTO(out, rc);
        }

        /* already recorded */
        if ( offset >= oe->oe_start && offset <= oe->oe_end )
                GOTO(out, rc);

        /* ok, need to check for adjacent neighbours */
        needle.oe_start = offset;
        needle.oe_end = offset;
        if (ot_find_oe(&ot->ot_root, &needle))
                GOTO(out, rc);

        /* ok, its safe to extend the oe we found */
        if ( offset == oe->oe_start - 1 )
                oe->oe_start--;
        else if ( offset == oe->oe_end + 1 )
                oe->oe_end++;
        else
                LBUG();
        ot->ot_num_marked++;

out:
        CDEBUG(D_INODE, "%lu now dirty\n", ot->ot_num_marked);
        spin_unlock(&ot->ot_lock);
        if (new_oe)
                OBD_FREE(new_oe, sizeof(*new_oe));
        RETURN(rc);
}

int ot_clear_extent(struct otree *ot, unsigned long start, unsigned long end)
{
        struct offset_extent needle, *oe, *new_oe;
        int rc = 0;
        ENTRY;

        /* will allocate more intelligently later */
        OBD_ALLOC(new_oe, sizeof(*new_oe));
        if (new_oe == NULL)
                RETURN(-ENOMEM);

        needle.oe_start = start;
        needle.oe_end = end;

        spin_lock(&ot->ot_lock);
        for ( ; (oe = ot_find_oe(&ot->ot_root, &needle)) ; ) {
                rc = 0;

                /* see if we're punching a hole and need to create a node */
                if (oe->oe_start < start && oe->oe_end > end) {
                        new_oe->oe_start = end + 1;
                        new_oe->oe_end = oe->oe_end;
                        oe->oe_end = start - 1;
                        ot_insert_oe(&ot->ot_root, new_oe);
                        new_oe = NULL;
                        ot->ot_num_marked -= end - start + 1;
                        break;
                }

                /* overlapping edges */
                if (oe->oe_start < start && oe->oe_end <= end) {
                        ot->ot_num_marked -= oe->oe_end - start + 1;
                        oe->oe_end = start - 1;
                        oe = NULL;
                        continue;
                }
                if (oe->oe_end > end && oe->oe_start >= start) {
                        ot->ot_num_marked -= end - oe->oe_start + 1;
                        oe->oe_start = end + 1;
                        oe = NULL;
                        continue;
                }

                /* an extent entirely within the one we're clearing */
                rb_erase(&oe->oe_node, &ot->ot_root);
                ot->ot_num_marked -= oe->oe_end - oe->oe_start + 1;
                spin_unlock(&ot->ot_lock);
                OBD_FREE(oe, sizeof(*oe));
                spin_lock(&ot->ot_lock);
        }
        CDEBUG(D_INODE, "%lu now dirty\n", ot->ot_num_marked);
        spin_unlock(&ot->ot_lock);
        if (new_oe)
                OBD_FREE(new_oe, sizeof(*new_oe));
        RETURN(rc);
}

int ot_find_marked_extent(struct otree *ot, unsigned long *start,
                  unsigned long *end)
{
        struct offset_extent needle, *oe;
        int rc = -ENOENT;
        ENTRY;

        needle.oe_start = *start;
        needle.oe_end = *end;

        spin_lock(&ot->ot_lock);
        oe = ot_find_oe(&ot->ot_root, &needle);
        if (oe) {
                *start = oe->oe_start;
                *end = oe->oe_end;
                rc = 0;
        }
        spin_unlock(&ot->ot_lock);

        RETURN(rc);
}

int ot_last_marked(struct otree *ot, unsigned long *last)
{
        struct rb_node_s *found, *node;
        struct offset_extent *oe;
        int rc = -ENOENT;
        ENTRY;

        spin_lock(&ot->ot_lock);
        for (node = ot->ot_root.rb_node, found = NULL;
             node;
             found = node, node = node->rb_right)
                ;

        if (found) {
                oe = rb_entry(found, struct offset_extent, oe_node);
                *last = oe->oe_end;
                rc = 0;
        }
        spin_unlock(&ot->ot_lock);
        RETURN(rc);
}

unsigned long ot_num_marked(struct otree *ot)
{
        return ot->ot_num_marked;
}

void ot_init(struct otree *ot)
{
        CDEBUG(D_INODE, "initializing %p\n", ot);
        spin_lock_init(&ot->ot_lock);
        ot->ot_num_marked = 0;
        ot->ot_root.rb_node = NULL;
}

EXPORT_SYMBOL(ot_mark_offset);
EXPORT_SYMBOL(ot_clear_extent);
EXPORT_SYMBOL(ot_find_marked_extent);
EXPORT_SYMBOL(ot_last_marked);
EXPORT_SYMBOL(ot_num_marked);
EXPORT_SYMBOL(ot_init);
