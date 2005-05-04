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

#define DEBUG_SUBSYSTEM S_PORTALS

#include <portals/lib-p30.h>

ptl_err_t
PtlMEAttach(ptl_handle_ni_t interface, 
            ptl_pt_index_t portal,
            ptl_process_id_t match_id, 
            ptl_match_bits_t match_bits,
            ptl_match_bits_t ignore_bits,
            ptl_unlink_t unlink, ptl_ins_pos_t pos, 
            ptl_handle_me_t *handle)
{
        ptl_me_t      *me;
        unsigned long  flags;

        LASSERT (ptl_apini.apini_init);
        LASSERT (ptl_apini.apini_refcount > 0);
        
        if (portal >= ptl_apini.apini_nportals)
                return PTL_PT_INDEX_INVALID;

        me = ptl_me_alloc();
        if (me == NULL)
                return PTL_NO_SPACE;

        PTL_LOCK(flags);

        me->me_match_id = match_id;
        me->me_match_bits = match_bits;
        me->me_ignore_bits = ignore_bits;
        me->me_unlink = unlink;
        me->me_md = NULL;

        ptl_initialise_handle (&me->me_lh, PTL_COOKIE_TYPE_ME);

        if (pos == PTL_INS_AFTER)
                list_add_tail(&me->me_list, &(ptl_apini.apini_portals[portal]));
        else
                list_add(&me->me_list, &(ptl_apini.apini_portals[portal]));

        ptl_me2handle(handle, me);

        PTL_UNLOCK(flags);

        return PTL_OK;
}

ptl_err_t 
PtlMEInsert(ptl_handle_me_t current_meh, 
            ptl_process_id_t match_id, 
            ptl_match_bits_t match_bits, 
            ptl_match_bits_t ignore_bits,
            ptl_unlink_t unlink, ptl_ins_pos_t pos,
            ptl_handle_me_t *handle)
{
        ptl_me_t     *current_me;
        ptl_me_t     *new_me;
        unsigned long flags;

        LASSERT (ptl_apini.apini_init);        
        LASSERT (ptl_apini.apini_refcount > 0);
        
        new_me = ptl_me_alloc();
        if (new_me == NULL)
                return PTL_NO_SPACE;

        PTL_LOCK(flags);

        current_me = ptl_handle2me(&current_meh);
        if (current_me == NULL) {
                ptl_me_free (new_me);

                PTL_UNLOCK(flags);
                return PTL_ME_INVALID;
        }

        new_me->me_match_id = match_id;
        new_me->me_match_bits = match_bits;
        new_me->me_ignore_bits = ignore_bits;
        new_me->me_unlink = unlink;
        new_me->me_md = NULL;

        ptl_initialise_handle (&new_me->me_lh, PTL_COOKIE_TYPE_ME);

        if (pos == PTL_INS_AFTER)
                list_add_tail(&new_me->me_list, &current_me->me_list);
        else
                list_add(&new_me->me_list, &current_me->me_list);

        ptl_me2handle(handle, new_me);

        PTL_UNLOCK(flags);

        return PTL_OK;
}

ptl_err_t
PtlMEUnlink(ptl_handle_me_t meh)
{
        unsigned long flags;
        ptl_me_t     *me;
        int           rc;

        LASSERT (ptl_apini.apini_init);        
        LASSERT (ptl_apini.apini_refcount > 0);
        
        PTL_LOCK(flags);

        me = ptl_handle2me(&meh);
        if (me == NULL) {
                rc = PTL_ME_INVALID;
        } else {
                ptl_me_unlink(me);
                rc = PTL_OK;
        }

        PTL_UNLOCK(flags);

        return (rc);
}

/* call with PTL_LOCK please */
void
ptl_me_unlink(ptl_me_t *me)
{
        list_del (&me->me_list);

        if (me->me_md) {
                me->me_md->md_me = NULL;
                ptl_md_unlink(me->me_md);
        }

        ptl_invalidate_handle (&me->me_lh);
        ptl_me_free(me);
}

#if 0
static void
lib_me_dump(ptl_me_t *me)
{
        CWARN("Match Entry %p ("LPX64")\n", me,
              me->me_lh.lh_cookie);

        CWARN("\tMatch/Ignore\t= %016lx / %016lx\n",
              me->me_match_bits, me->me_ignore_bits);

        CWARN("\tMD\t= %p\n", me->md);
        CWARN("\tprev\t= %p\n",
              list_entry(me->me_list.prev, ptl_me_t, me_list));
        CWARN("\tnext\t= %p\n",
              list_entry(me->me_list.next, ptl_me_t, me_list));
}
#endif
