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

#ifndef __KERNEL__
# include <stdio.h>
#else
# define DEBUG_SUBSYSTEM S_PORTALS
# include <linux/kp30.h>
#endif

#include <portals/lib-p30.h>

int
lib_api_me_attach(nal_t *apinal,
                  ptl_pt_index_t portal,
                  ptl_process_id_t match_id, 
                  ptl_match_bits_t match_bits, 
                  ptl_match_bits_t ignore_bits,
                  ptl_unlink_t unlink, ptl_ins_pos_t pos,
                  ptl_handle_me_t *handle)
{
        lib_nal_t    *nal = apinal->nal_data;
        lib_ni_t     *ni = &nal->libnal_ni;
        lib_ptl_t    *tbl = &ni->ni_portals;
        lib_me_t     *me;
        unsigned long flags;

        if (portal >= tbl->size)
                return PTL_PT_INDEX_INVALID;

        me = lib_me_alloc (nal);
        if (me == NULL)
                return PTL_NO_SPACE;

        LIB_LOCK(nal, flags);

        me->match_id = match_id;
        me->match_bits = match_bits;
        me->ignore_bits = ignore_bits;
        me->unlink = unlink;
        me->md = NULL;

        lib_initialise_handle (nal, &me->me_lh, PTL_COOKIE_TYPE_ME);

        if (pos == PTL_INS_AFTER)
                list_add_tail(&me->me_list, &(tbl->tbl[portal]));
        else
                list_add(&me->me_list, &(tbl->tbl[portal]));

        ptl_me2handle(handle, nal, me);

        LIB_UNLOCK(nal, flags);

        return PTL_OK;
}

int
lib_api_me_insert(nal_t *apinal,
                  ptl_handle_me_t *current_meh,
                  ptl_process_id_t match_id, 
                  ptl_match_bits_t match_bits, 
                  ptl_match_bits_t ignore_bits,
                  ptl_unlink_t unlink, ptl_ins_pos_t pos,
                  ptl_handle_me_t *handle)
{
        lib_nal_t    *nal = apinal->nal_data;
        lib_me_t     *current_me;
        lib_me_t     *new_me;
        unsigned long flags;

        new_me = lib_me_alloc (nal);
        if (new_me == NULL)
                return PTL_NO_SPACE;

        LIB_LOCK(nal, flags);

        current_me = ptl_handle2me(current_meh, nal);
        if (current_me == NULL) {
                lib_me_free (nal, new_me);

                LIB_UNLOCK(nal, flags);
                return PTL_ME_INVALID;
        }

        new_me->match_id = match_id;
        new_me->match_bits = match_bits;
        new_me->ignore_bits = ignore_bits;
        new_me->unlink = unlink;
        new_me->md = NULL;

        lib_initialise_handle (nal, &new_me->me_lh, PTL_COOKIE_TYPE_ME);

        if (pos == PTL_INS_AFTER)
                list_add_tail(&new_me->me_list, &current_me->me_list);
        else
                list_add(&new_me->me_list, &current_me->me_list);

        ptl_me2handle(handle, nal, new_me);

        LIB_UNLOCK(nal, flags);

        return PTL_OK;
}

int
lib_api_me_unlink (nal_t *apinal, ptl_handle_me_t *meh)
{
        lib_nal_t    *nal = apinal->nal_data;
        unsigned long flags;
        lib_me_t     *me;
        int           rc;

        LIB_LOCK(nal, flags);

        me = ptl_handle2me(meh, nal);
        if (me == NULL) {
                rc = PTL_ME_INVALID;
        } else {
                lib_me_unlink(nal, me);
                rc = PTL_OK;
        }

        LIB_UNLOCK(nal, flags);

        return (rc);
}

/* call with state_lock please */
void 
lib_me_unlink(lib_nal_t *nal, lib_me_t *me)
{
        list_del (&me->me_list);

        if (me->md) {
                me->md->me = NULL;
                lib_md_unlink(nal, me->md);
        }

        lib_invalidate_handle (nal, &me->me_lh);
        lib_me_free(nal, me);
}

#if 0
static void 
lib_me_dump(lib_nal_t *nal, lib_me_t * me)
{
        CWARN("Match Entry %p ("LPX64")\n", me, 
              me->me_lh.lh_cookie);

        CWARN("\tMatch/Ignore\t= %016lx / %016lx\n",
              me->match_bits, me->ignore_bits);

        CWARN("\tMD\t= %p\n", me->md);
        CWARN("\tprev\t= %p\n",
              list_entry(me->me_list.prev, lib_me_t, me_list));
        CWARN("\tnext\t= %p\n",
              list_entry(me->me_list.next, lib_me_t, me_list));
}
#endif
