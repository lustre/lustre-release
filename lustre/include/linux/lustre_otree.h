/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _LUSTRE_OTREE_H
#define _LUSTRE_OTREE_H

/* XXX ok, I can't make sense of our header nest right now.. */
#ifdef __KERNEL__
#include <linux/rbtree.h>
#include <linux/spinlock.h>

struct otree {
        rb_root_t       ot_root;
        spinlock_t      ot_lock;
        unsigned long   ot_num_marked;
};
#else
struct otree {
        unsigned long   lalala;
};
#endif

int ot_mark_offset(struct otree *ot, unsigned long offset);
int ot_clear_extent(struct otree *ot, unsigned long start, unsigned long end);
int ot_find_marked_extent(struct otree *ot, unsigned long *start,
                          unsigned long *end);
int ot_last_marked(struct otree *ot, unsigned long *last);
unsigned long ot_num_marked(struct otree *ot);
void ot_init(struct otree *ot);

#endif
