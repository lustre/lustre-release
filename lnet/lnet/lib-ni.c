/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *   This file is not subject to copyright protection.
 */

#define DEBUG_SUBSYSTEM S_PORTALS
#include <portals/lib-p30.h>

int lib_api_ni_status (nal_t *apinal, ptl_sr_index_t sr_idx,
                       ptl_sr_value_t *status)
{
        return PTL_FAIL;
}


int lib_api_ni_dist (nal_t *apinal, ptl_process_id_t *pid, unsigned long *dist)
{
        lib_nal_t *nal = apinal->nal_data;

        return (nal->libnal_dist(nal, pid->nid, dist));
}
