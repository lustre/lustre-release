/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * api/api-init.c
 * Initialization and global data for the p30 user side library
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

#include <portals/api-support.h>

int PtlInit(int *max_interfaces)
{
        if (max_interfaces != NULL)
                *max_interfaces = NAL_MAX_NR;

        LASSERT(!strcmp(ptl_err_str[PTL_MAX_ERRNO], "PTL_MAX_ERRNO"));

        return ptl_ni_init();
}


void PtlFini(void)
{
        ptl_ni_fini();
}


void PtlSnprintHandle(char *str, int len, ptl_handle_any_t h)
{
        snprintf(str, len, "0x%lx."LPX64, h.nal_idx, h.cookie);
}
