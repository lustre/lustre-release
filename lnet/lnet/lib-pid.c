/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-pid.c
 *
 * Process identification routines
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *
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

/* This should be removed.  The NAL should have the PID information */
#define DEBUG_SUBSYSTEM S_PORTALS

#if defined (__KERNEL__)
#       include <linux/kernel.h>
extern int getpid(void);
#else
#       include <stdio.h>
#       include <unistd.h>
#endif
#include <portals/lib-p30.h>
#include <portals/arg-blocks.h>

int do_PtlGetId(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_ni_t handle_in
         *
         * Outgoing:
         *      ptl_process_id_t        * id_out
         *      ptl_id_t                * gsize_out
         */

        PtlGetId_out *ret = v_ret;
        lib_ni_t *ni = &nal->ni;

        ret->id_out.nid = ni->nid;
        ret->id_out.pid = ni->pid;

        return ret->rc = PTL_OK;
}
