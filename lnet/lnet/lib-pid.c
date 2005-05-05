/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *   This file is not subject to copyright protection.
 */

/* This should be removed.  The NAL should have the PID information */
#define DEBUG_SUBSYSTEM S_PORTALS

#include <portals/lib-p30.h>

int
lib_api_get_id(nal_t *apinal, ptl_process_id_t *pid)
{
        lib_nal_t *nal = apinal->nal_data;
        
        *pid = nal->libnal_ni.ni_pid;
        return PTL_OK;
}
