/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-ni.c
 * Network status registers and distance functions.
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

#define MAX_DIST 18446744073709551615UL

int do_PtlNIDebug(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        PtlNIDebug_in *args = v_args;
        PtlNIDebug_out *ret = v_ret;
        lib_ni_t *ni = &nal->ni;

        ret->rc = ni->debug;
        ni->debug = args->mask_in;

        return 0;
}

int do_PtlNIStatus(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_ni_t interface_in
         *      ptl_sr_index_t register_in
         *
         * Outgoing:
         *      ptl_sr_value_t          * status_out
         */

        PtlNIStatus_in *args = v_args;
        PtlNIStatus_out *ret = v_ret;
        lib_ni_t *ni = &nal->ni;
        lib_counters_t *count = &ni->counters;

        if (!args)
                return ret->rc = PTL_SEGV;

        ret->rc = PTL_OK;
        ret->status_out = 0;

        /*
         * I hate this sort of code....  Hash tables, offset lists?
         * Treat the counters as an array of ints?
         */
        if (args->register_in == PTL_SR_DROP_COUNT)
                ret->status_out = count->drop_count;

        else if (args->register_in == PTL_SR_DROP_LENGTH)
                ret->status_out = count->drop_length;

        else if (args->register_in == PTL_SR_RECV_COUNT)
                ret->status_out = count->recv_count;

        else if (args->register_in == PTL_SR_RECV_LENGTH)
                ret->status_out = count->recv_length;

        else if (args->register_in == PTL_SR_SEND_COUNT)
                ret->status_out = count->send_count;

        else if (args->register_in == PTL_SR_SEND_LENGTH)
                ret->status_out = count->send_length;

        else if (args->register_in == PTL_SR_MSGS_MAX)
                ret->status_out = count->msgs_max;
        else
                ret->rc = PTL_INV_SR_INDX;

        return ret->rc;
}


int do_PtlNIDist(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_ni_t interface_in
         *      ptl_process_id_t process_in

         *
         * Outgoing:
         *      unsigned long   * distance_out

         */

        PtlNIDist_in *args = v_args;
        PtlNIDist_out *ret = v_ret;

        unsigned long dist;
        ptl_process_id_t id_in = args->process_in;
        ptl_nid_t nid;
        int rc;

        nid = id_in.nid;

        if ((rc = nal->cb_dist(nal, nid, &dist)) != 0) {
                ret->distance_out = (unsigned long) MAX_DIST;
                return PTL_INV_PROC;
        }

        ret->distance_out = dist;

        return ret->rc = PTL_OK;
}
