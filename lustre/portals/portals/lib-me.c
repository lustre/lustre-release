/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-me.c
 * Match Entry management routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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
#include <portals/arg-blocks.h>

static void lib_me_dump(nal_cb_t * nal, lib_me_t * me);

int do_PtlMEAttach(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        PtlMEAttach_in *args = v_args;
        PtlMEAttach_out *ret = v_ret;
        lib_ni_t *ni = &nal->ni;
        lib_ptl_t *tbl = &ni->tbl;
        unsigned long flags;
        lib_me_t *me;

        if (args->index_in < 0 || args->index_in >= tbl->size)
                return ret->rc = PTL_INV_PTINDEX;

        /* Should check for valid matchid, but not yet */
        if (0)
                return ret->rc = PTL_INV_PROC;

        me = lib_me_alloc (nal);
        if (me == NULL)
                return (ret->rc = PTL_NOSPACE);

        state_lock(nal, &flags);

        me->match_id = args->match_id_in;
        me->match_bits = args->match_bits_in;
        me->ignore_bits = args->ignore_bits_in;
        me->unlink = args->unlink_in;
        me->md = NULL;

        lib_initialise_handle (nal, &me->me_lh);

        if (args->position_in == PTL_INS_AFTER)
                list_add_tail(&me->me_list, &(tbl->tbl[args->index_in]));
        else
                list_add(&me->me_list, &(tbl->tbl[args->index_in]));

        ptl_me2handle(&ret->handle_out, me);

        state_unlock(nal, &flags);

        return ret->rc = PTL_OK;
}

int do_PtlMEInsert(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        PtlMEInsert_in *args = v_args;
        PtlMEInsert_out *ret = v_ret;
        unsigned long flags;
        lib_me_t *me;
        lib_me_t *new;

        new = lib_me_alloc (nal);
        if (new == NULL)
                return (ret->rc = PTL_NOSPACE);

        /* Should check for valid matchid, but not yet */

        state_lock(nal, &flags);

        me = ptl_handle2me(&args->current_in, nal);
        if (me == NULL) {
                lib_me_free (nal, new);

                state_unlock (nal, &flags);
                return (ret->rc = PTL_INV_ME);
        }

        new->match_id = args->match_id_in;
        new->match_bits = args->match_bits_in;
        new->ignore_bits = args->ignore_bits_in;
        new->unlink = args->unlink_in;
        new->md = NULL;

        lib_initialise_handle (nal, &new->me_lh);

        if (args->position_in == PTL_INS_AFTER)
                list_add_tail(&new->me_list, &me->me_list);
        else
                list_add(&new->me_list, &me->me_list);

        ptl_me2handle(&ret->handle_out, new);

        state_unlock(nal, &flags);

        return ret->rc = PTL_OK;
}

int do_PtlMEUnlink(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        PtlMEUnlink_in *args = v_args;
        PtlMEUnlink_out *ret = v_ret;
        unsigned long flags;
        lib_me_t *me;

        state_lock(nal, &flags);

        me = ptl_handle2me(&args->current_in, nal);
        if (me == NULL) {
                ret->rc = PTL_INV_ME;
        } else {
                lib_me_unlink(nal, me);
                ret->rc = PTL_OK;
        }

        state_unlock(nal, &flags);

        return (ret->rc);
}

/* call with state_lock please */
void lib_me_unlink(nal_cb_t *nal, lib_me_t *me)
{
        lib_ni_t *ni = &nal->ni;

        if (ni->debug & PTL_DEBUG_UNLINK) {
                ptl_handle_any_t handle;
                ptl_me2handle(&handle, me);
        }

        list_del (&me->me_list);

        if (me->md) {
                me->md->me = NULL;
                lib_md_unlink(nal, me->md);
        }

        lib_invalidate_handle (nal, &me->me_lh);
        lib_me_free(nal, me);
}

int do_PtlTblDump(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        PtlTblDump_in *args = v_args;
        PtlTblDump_out *ret = v_ret;
        lib_ptl_t *tbl = &nal->ni.tbl;
        ptl_handle_any_t handle;
        struct list_head *tmp;
        unsigned long flags;

        if (args->index_in < 0 || args->index_in >= tbl->size)
                return ret->rc = PTL_INV_PTINDEX;

        nal->cb_printf(nal, "Portal table index %d\n", args->index_in);

        state_lock(nal, &flags);
        list_for_each(tmp, &(tbl->tbl[args->index_in])) {
                lib_me_t *me = list_entry(tmp, lib_me_t, me_list);
                ptl_me2handle(&handle, me);
                lib_me_dump(nal, me);
        }
        state_unlock(nal, &flags);

        return ret->rc = PTL_OK;
}

int do_PtlMEDump(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        PtlMEDump_in *args = v_args;
        PtlMEDump_out *ret = v_ret;
        lib_me_t *me;
        unsigned long flags;

        state_lock(nal, &flags);

        me = ptl_handle2me(&args->current_in, nal);
        if (me == NULL) {
                ret->rc = PTL_INV_ME;
        } else {
                lib_me_dump(nal, me);
                ret->rc = PTL_OK;
        }

        state_unlock(nal, &flags);

        return ret->rc;
}

static void lib_me_dump(nal_cb_t * nal, lib_me_t * me)
{
        nal->cb_printf(nal, "Match Entry %p ("LPX64")\n", me, 
                       me->me_lh.lh_cookie);

        nal->cb_printf(nal, "\tMatch/Ignore\t= %016lx / %016lx\n",
                       me->match_bits, me->ignore_bits);

        nal->cb_printf(nal, "\tMD\t= %p\n", me->md);
        nal->cb_printf(nal, "\tprev\t= %p\n",
                       list_entry(me->me_list.prev, lib_me_t, me_list));
        nal->cb_printf(nal, "\tnext\t= %p\n",
                       list_entry(me->me_list.next, lib_me_t, me_list));
}
