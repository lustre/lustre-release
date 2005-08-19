/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 *
 *   This file is part of Lustre, http://www.lustre.org/
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

#include "gmnal.h"


/*
 *      -1 indicates default value.
 *      This is 1 thread per cpu
 *      See start_kernel_threads
 */
int num_rx_threads = -1;
int num_txds = 5;
int gm_port_id = 4;

static int __init
gmnal_load(void)
{
	int	status;
	CDEBUG(D_TRACE, "This is the gmnal module initialisation routine\n");


	CDEBUG(D_NET, "Calling gmnal_init\n");
        status = gmnal_init();
	if (status == PTL_OK) {
		CDEBUG(D_NET, "Portals GMNAL initialised ok\n");
	} else {
		CDEBUG(D_NET, "Portals GMNAL Failed to initialise\n");
		return(-ENODEV);
	}

	CDEBUG(D_NET, "This is the end of the gmnal init routine");

	return(0);
}


static void __exit
gmnal_unload(void)
{
	gmnal_fini();
	return;
}


module_init(gmnal_load);
module_exit(gmnal_unload);

MODULE_PARM(num_rx_threads, "i");
MODULE_PARM(num_txds, "i");
MODULE_PARM(gm_port_id, "i");

MODULE_AUTHOR("Morgan Doyle");

MODULE_DESCRIPTION("A Portals kernel NAL for Myrinet GM.");

MODULE_LICENSE("GPL");
