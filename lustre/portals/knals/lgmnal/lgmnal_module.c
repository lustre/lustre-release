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

#include "lgmnal.h"


int lgmnal_small_msg_size = 525312;
/*
 *      -1 indicates default value.
 *      This is 1 thread per cpu
 *      See start_kernel_threads
 */
int num_rx_threads = -1;

ptl_handle_ni_t	lgmnal_ni;


int 
lgmnal_cmd(struct portal_ioctl_data *data, void *private)
{
	lgmnal_data_t	*nal_data = NULL;
	char		*name = NULL;
	int		nid = -2;
	int		gnid;
	gm_status_t	gm_status;


	CDEBUG(D_TRACE, "lgmnal_cmd [%d] private [%p]\n", 
	       data->ioc_nal_cmd, private);
	nal_data = (lgmnal_data_t*)private;
	switch(data->ioc_nal_cmd) {
	/*
	 * just reuse already defined GET_NID. Should define LGMNAL version
	 */
	case(LGMNAL_IOC_GET_GNID):

		PORTAL_ALLOC(name, data->ioc_plen1);
		copy_from_user(name, data->ioc_pbuf1, data->ioc_plen1);
	
		LGMNAL_GM_LOCK(nal_data);
		nid = gm_host_name_to_node_id(nal_data->gm_port, name);
		LGMNAL_GM_UNLOCK(nal_data);
		CDEBUG(D_INFO, "Local node id is [%d]\n", nid);
		LGMNAL_GM_LOCK(nal_data);
		gm_status = gm_node_id_to_global_id(nal_data->gm_port, 
						    nid, &gnid);
		LGMNAL_GM_UNLOCK(nal_data);
		if (gm_status != GM_SUCCESS) {
			CDEBUG(D_INFO, "gm_node_id_to_global_id failed[%d]\n", 
			       gm_status);
			return(-1);
		}
		CDEBUG(D_INFO, "Global node is is [%u][%x]\n", gnid, gnid);
		copy_to_user(data->ioc_pbuf2, &gnid, data->ioc_plen2);
	break;
	default:
		CDEBUG(D_INFO, "lgmnal_cmd UNKNOWN[%d]\n", data->ioc_nal_cmd);
		data->ioc_nid2 = -1;
	}


	return(0);
}


static int __init
lgmnal_load(void)
{
	int	status;
	CDEBUG(D_TRACE, "This is the lgmnal module initialisation routine\n");



	CDEBUG(D_INFO, "Calling lgmnal_init\n");
	status = PtlNIInit(lgmnal_init, 32, 4, 0, &lgmnal_ni);
	if (status == PTL_OK) {
		CDEBUG(D_INFO, "Portals LGMNAL initialised ok lgmnal_ni\n");
	} else {
		CDEBUG(D_INFO, "Portals LGMNAL Failed to initialise\n");
		return(1);
		
	}

	CDEBUG(D_INFO, "Calling kportal_nal_register\n");
	/*
 	 *	global_nal_data is set by lgmnal_init
	 */
	if (kportal_nal_register(LGMNAL, &lgmnal_cmd, global_nal_data) != 0) {
		CDEBUG(D_INFO, "kportal_nal_register failed\n");
		return(1);
	}

	CDEBUG(D_INFO, "Calling PORTAL_SYMBOL_REGISTER\n");
	PORTAL_SYMBOL_REGISTER(lgmnal_ni);
	CDEBUG(D_INFO, "This is the end of the lgmnal init routine");


	return(0);
}


static void __exit
lgmnal_unload(void)
{

	kportal_nal_unregister(LGMNAL);
	PORTAL_SYMBOL_UNREGISTER(lgmnal_ni);
	lgmnal_fini();
	global_nal_data = NULL;
	return;
}


module_init(lgmnal_load);

module_exit(lgmnal_unload);

EXPORT_SYMBOL(lgmnal_ni);

MODULE_PARM(lgmnal_small_msg_size, "i");
MODULE_PARM(num_rx_threads, "i");

MODULE_AUTHOR("Morgan Doyle");

MODULE_DESCRIPTION("A Portals kernel NAL for Myrinet GM.");

MODULE_LICENSE("GPL");
