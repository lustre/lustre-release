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

int ptl_init;
unsigned int portal_subsystem_debug = 0xfff7e3ff;
unsigned int portal_debug = ~0;
unsigned int portal_printk;
unsigned int portal_stack;

#ifdef __KERNEL__
atomic_t portal_kmemory = ATOMIC_INIT(0);
#endif

int __p30_initialized;
int __p30_myr_initialized;
int __p30_ip_initialized;
ptl_handle_ni_t __myr_ni_handle;
ptl_handle_ni_t __ip_ni_handle;

int __p30_myr_timeout = 10;
int __p30_ip_timeout;

int PtlInit(void)
{

        if (ptl_init)
                return PTL_OK;

        ptl_ni_init();
        ptl_me_init();
        ptl_eq_init();
        ptl_init = 1;
        __p30_initialized = 1;

        return PTL_OK;
}


void PtlFini(void)
{

        /* Reverse order of initialization */
        ptl_eq_fini();
        ptl_me_fini();
        ptl_ni_fini();
        ptl_init = 0;
}
