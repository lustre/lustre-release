/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-me.c
 * Match Entry management routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org
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
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>

int
LNetMEAttach(unsigned int portal,
             lnet_process_id_t match_id, 
             __u64 match_bits, __u64 ignore_bits,
             lnet_unlink_t unlink, lnet_ins_pos_t pos, 
             lnet_handle_me_t *handle)
{
        lnet_me_t     *me;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);
        
        if (portal >= the_lnet.ln_nportals)
                return -EINVAL;

        me = lnet_me_alloc();
        if (me == NULL)
                return -ENOMEM;

        LNET_LOCK();

        me->me_portal = portal;
        me->me_match_id = match_id;
        me->me_match_bits = match_bits;
        me->me_ignore_bits = ignore_bits;
        me->me_unlink = unlink;
        me->me_md = NULL;

        lnet_initialise_handle (&me->me_lh, LNET_COOKIE_TYPE_ME);

        if (pos == LNET_INS_AFTER)
                list_add_tail(&me->me_list, &(the_lnet.ln_portals[portal].ptl_ml));
        else
                list_add(&me->me_list, &(the_lnet.ln_portals[portal].ptl_ml));

        lnet_me2handle(handle, me);

        LNET_UNLOCK();

        return 0;
}

int 
LNetMEInsert(lnet_handle_me_t current_meh, 
             lnet_process_id_t match_id, 
             __u64 match_bits, __u64 ignore_bits,
             lnet_unlink_t unlink, lnet_ins_pos_t pos,
             lnet_handle_me_t *handle)
{
        lnet_me_t     *current_me;
        lnet_me_t     *new_me;

        LASSERT (the_lnet.ln_init);        
        LASSERT (the_lnet.ln_refcount > 0);
        
        new_me = lnet_me_alloc();
        if (new_me == NULL)
                return -ENOMEM;

        LNET_LOCK();

        current_me = lnet_handle2me(&current_meh);
        if (current_me == NULL) {
                lnet_me_free (new_me);

                LNET_UNLOCK();
                return -ENOENT;
        }

        new_me->me_match_id = match_id;
        new_me->me_match_bits = match_bits;
        new_me->me_ignore_bits = ignore_bits;
        new_me->me_unlink = unlink;
        new_me->me_md = NULL;

        lnet_initialise_handle (&new_me->me_lh, LNET_COOKIE_TYPE_ME);

        if (pos == LNET_INS_AFTER)
                list_add_tail(&new_me->me_list, &current_me->me_list);
        else
                list_add(&new_me->me_list, &current_me->me_list);

        lnet_me2handle(handle, new_me);

        LNET_UNLOCK();

        return 0;
}

int
LNetMEUnlink(lnet_handle_me_t meh)
{
        lnet_me_t     *me;
        int           rc;

        LASSERT (the_lnet.ln_init);        
        LASSERT (the_lnet.ln_refcount > 0);
        
        LNET_LOCK();

        me = lnet_handle2me(&meh);
        if (me == NULL) {
                rc = -ENOENT;
        } else {
                lnet_me_unlink(me);
                rc = 0;
        }

        LNET_UNLOCK();

        return (rc);
}

/* call with LNET_LOCK please */
void
lnet_me_unlink(lnet_me_t *me)
{
        list_del (&me->me_list);

        if (me->me_md) {
                me->me_md->md_me = NULL;
                lnet_md_unlink(me->me_md);
        }

        lnet_invalidate_handle (&me->me_lh);
        lnet_me_free(me);
}

#if 0
static void
lib_me_dump(lnet_me_t *me)
{
        CWARN("Match Entry %p ("LPX64")\n", me,
              me->me_lh.lh_cookie);

        CWARN("\tMatch/Ignore\t= %016lx / %016lx\n",
              me->me_match_bits, me->me_ignore_bits);

        CWARN("\tMD\t= %p\n", me->md);
        CWARN("\tprev\t= %p\n",
              list_entry(me->me_list.prev, lnet_me_t, me_list));
        CWARN("\tnext\t= %p\n",
              list_entry(me->me_list.next, lnet_me_t, me_list));
}
#endif
