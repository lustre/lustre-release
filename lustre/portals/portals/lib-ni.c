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

#define MAX_DIST 18446744073709551615ULL

int lib_api_ni_status (nal_t *apinal, ptl_sr_index_t sr_idx,
                       ptl_sr_value_t *status)
{
        lib_nal_t      *nal = apinal->nal_data;
        lib_ni_t       *ni = &nal->libnal_ni;
        lib_counters_t *count = &ni->ni_counters;

        switch (sr_idx) {
        case PTL_SR_DROP_COUNT:
                *status = count->drop_count;
                return PTL_OK;
        case PTL_SR_DROP_LENGTH:
                *status = count->drop_length;
                return PTL_OK;
        case PTL_SR_RECV_COUNT:
                *status = count->recv_count;
                return PTL_OK;
        case PTL_SR_RECV_LENGTH:
                *status = count->recv_length;
                return PTL_OK;
        case PTL_SR_SEND_COUNT:
                *status = count->send_count;
                return PTL_OK;
        case PTL_SR_SEND_LENGTH:
                *status = count->send_length;
                return PTL_OK;
        case PTL_SR_MSGS_MAX:
                *status = count->msgs_max;
                return PTL_OK;
        default:
                *status = 0;
                return PTL_SR_INDEX_INVALID;
        }
}


int lib_api_ni_dist (nal_t *apinal, ptl_process_id_t *pid, unsigned long *dist)
{
        lib_nal_t *nal = apinal->nal_data;

        return (nal->libnal_dist(nal, pid->nid, dist));
}
