/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-eq.c
 * Library level Event queue management routines
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

#define DEBUG_SUBSYSTEM S_PORTALS
#include <portals/lib-p30.h>
#include <portals/arg-blocks.h>

int do_PtlEQAlloc_internal(nal_cb_t * nal, void *private, void *v_args,
                           void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_ni_t ni_in
         *      ptl_size_t count_in
         *      void                    * base_in
         *
         * Outgoing:
         *      ptl_handle_eq_t         * handle_out
         */

        PtlEQAlloc_in *args = v_args;
        PtlEQAlloc_out *ret = v_ret;

        lib_eq_t *eq;
        unsigned long flags;

        /* api should have rounded up */
        if (args->count_in != LOWEST_BIT_SET (args->count_in))
                return ret->rc = PTL_VAL_FAILED;

        eq = lib_eq_alloc (nal);
        if (eq == NULL)
                return (ret->rc = PTL_NOSPACE);

        state_lock(nal, &flags);

        if (nal->cb_map != NULL) {
                struct iovec iov = {
                        .iov_base = args->base_in,
                        .iov_len = args->count_in * sizeof (ptl_event_t) };

                ret->rc = nal->cb_map (nal, 1, &iov, &eq->eq_addrkey);
                if (ret->rc != PTL_OK) {
                        lib_eq_free (nal, eq);
                        
                        state_unlock (nal, &flags);
                        return (ret->rc);
                }
        }

        eq->sequence = 1;
        eq->base = args->base_in;
        eq->size = args->count_in;
        eq->eq_refcount = 0;
        eq->event_callback = args->callback_in;

        lib_initialise_handle (nal, &eq->eq_lh);
        list_add (&eq->eq_list, &nal->ni.ni_active_eqs);

        state_unlock(nal, &flags);

        ptl_eq2handle(&ret->handle_out, eq);
        return (ret->rc = PTL_OK);
}

int do_PtlEQFree_internal(nal_cb_t * nal, void *private, void *v_args,
                          void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_eq_t eventq_in
         *
         * Outgoing:
         */

        PtlEQFree_in *args = v_args;
        PtlEQFree_out *ret = v_ret;
        lib_eq_t *eq;
        long flags;

        state_lock (nal, &flags);

        eq = ptl_handle2eq(&args->eventq_in, nal);
        if (eq == NULL) {
                ret->rc = PTL_INV_EQ;
        } else if (eq->eq_refcount != 0) {
                ret->rc = PTL_EQ_INUSE;
        } else {
                if (nal->cb_unmap != NULL) {
                        struct iovec iov = {
                                .iov_base = eq->base,
                                .iov_len = eq->size * sizeof (ptl_event_t) };
                        
                        nal->cb_unmap(nal, 1, &iov, &eq->eq_addrkey);
                }

                lib_invalidate_handle (nal, &eq->eq_lh);
                list_del (&eq->eq_list);
                lib_eq_free (nal, eq);
                ret->rc = PTL_OK;
        }

        state_unlock (nal, &flags);

        return (ret->rc);
}
