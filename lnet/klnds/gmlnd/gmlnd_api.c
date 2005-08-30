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

/*
 *	Implements the API NAL functions
 */

#include "gmnal.h"



gmnal_data_t	*global_nal_data = NULL;
#define         GLOBAL_NID_STR_LEN      16
char            global_nid_str[GLOBAL_NID_STR_LEN] = {0};

extern int gmnal_ctl(ptl_ni_t *ni, unsigned int cmd, void *arg);

/*
 *      Write the global nid /proc/sys/gmnal/globalnid
 */
#define GMNAL_SYSCTL    201
#define GMNAL_SYSCTL_GLOBALNID  1

static ctl_table gmnal_sysctl_table[] = {
        {GMNAL_SYSCTL_GLOBALNID, "globalnid",
         global_nid_str, GLOBAL_NID_STR_LEN,
         0444, NULL, &proc_dostring},
        { 0 }
};


static ctl_table gmnalnal_top_sysctl_table[] = {
        {GMNAL_SYSCTL, "gmnal", NULL, 0, 0555, gmnal_sysctl_table},
        { 0 }
};

/*
 *	gmnal_shutdown
 *	Close down this interface and free any resources associated with it
 *	nal_t	nal	our nal to shutdown
 */
void
gmnal_shutdown(ptl_ni_t *ni)
{
	gmnal_data_t	*nal_data;

        LASSERT(ni->ni_data == global_nal_data);

        nal_data = (gmnal_data_t *)ni->ni_data;
        LASSERT(nal_data == global_nal_data);
	CDEBUG(D_TRACE, "gmnal_shutdown: nal_data [%p]\n", nal_data);

        /* XXX for shutdown "under fire" we probably need to set a shutdown
         * flag so when portals calls us we fail immediately and dont queue any
         * more work but our threads can still call into portals OK.  THEN
         * shutdown our threads, THEN ptl_fini() */

	gmnal_stop_rxthread(nal_data);
	gmnal_stop_ctthread(nal_data);
	gmnal_free_txd(nal_data);
	gmnal_free_srxd(nal_data);
	GMNAL_GM_LOCK(nal_data);
	gm_close(nal_data->gm_port);
	gm_finalize();
	GMNAL_GM_UNLOCK(nal_data);
        if (nal_data->sysctl)
                unregister_sysctl_table (nal_data->sysctl);
        /* Don't free 'nal'; it's a static struct */
	PORTAL_FREE(nal_data, sizeof(gmnal_data_t));

        global_nal_data = NULL;

        PORTAL_MODULE_UNUSE;
}


int
gmnal_startup(ptl_ni_t *ni)
{
	gmnal_data_t	*nal_data = NULL;
	gmnal_srxd_t	*srxd = NULL;
	gm_status_t	gm_status;
	unsigned int	local_nid = 0, global_nid = 0;

	CDEBUG(D_TRACE, "startup\n");

        LASSERT(ni->ni_nal == &gmnal_nal);

        if (global_nal_data != NULL) {
                /* Already got 1 instance */
                CERROR("Can't support > 1 instance of this NAL\n");
                return -EPERM;
        }

        if (ni->ni_interfaces[0] != NULL) {
                CERROR("Explicit interface config not supported\n");
                return -EPERM;
        }
        
	PORTAL_ALLOC(nal_data, sizeof(gmnal_data_t));
	if (!nal_data) {
		CDEBUG(D_ERROR, "can't get memory\n");
		return(-ENOMEM);
	}	
	memset(nal_data, 0, sizeof(gmnal_data_t));
	/*
 	 *	set the small message buffer size 
	 */

	CDEBUG(D_INFO, "Allocd and reset nal_data[%p]\n", nal_data);
	CDEBUG(D_INFO, "small_msg_size is [%d]\n", nal_data->small_msg_size);

	/*
	 *	String them all together
	 */
        ni->ni_data = nal_data;
	nal_data->ni = ni;

	GMNAL_GM_LOCK_INIT(nal_data);


	/*
	 *	initialise the interface,
	 */
	CDEBUG(D_INFO, "Calling gm_init\n");
	if (gm_init() != GM_SUCCESS) {
		CDEBUG(D_ERROR, "call to gm_init failed\n");
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		return(-ENETDOWN);
	}


	CDEBUG(D_NET, "Calling gm_open with port [%d], "
	       "name [%s], version [%d]\n", GMNAL_GM_PORT_ID,
	       "gmnal", GM_API_VERSION);

	GMNAL_GM_LOCK(nal_data);
	gm_status = gm_open(&nal_data->gm_port, 0, GMNAL_GM_PORT_ID, "gmnal",
			    GM_API_VERSION);
	GMNAL_GM_UNLOCK(nal_data);

	CDEBUG(D_INFO, "gm_open returned [%d]\n", gm_status);
	if (gm_status == GM_SUCCESS) {
		CDEBUG(D_INFO, "gm_open succeeded port[%p]\n", 
		       nal_data->gm_port);
	} else {
		switch(gm_status) {
		case(GM_INVALID_PARAMETER):
			CDEBUG(D_ERROR, "gm_open Failure. Invalid Parameter\n");
			break;
		case(GM_BUSY):
			CDEBUG(D_ERROR, "gm_open Failure. GM Busy\n");
			break;
		case(GM_NO_SUCH_DEVICE):
			CDEBUG(D_ERROR, "gm_open Failure. No such device\n");
			break;
		case(GM_INCOMPATIBLE_LIB_AND_DRIVER):
			CDEBUG(D_ERROR, "gm_open Failure. Incompatile lib "
			       "and driver\n");
			break;
		case(GM_OUT_OF_MEMORY):
			CDEBUG(D_ERROR, "gm_open Failure. Out of Memory\n");
			break;
		default:
			CDEBUG(D_ERROR, "gm_open Failure. Unknow error "
			       "code [%d]\n", gm_status);
			break;
		}	
		GMNAL_GM_LOCK(nal_data);
		gm_finalize();
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		return(-ENETDOWN);
	}

	nal_data->small_msg_size = gmnal_small_msg_size;
	nal_data->small_msg_gmsize =
			gm_min_size_for_length(gmnal_small_msg_size);

	if (gmnal_alloc_srxd(nal_data) != GMNAL_STATUS_OK) {
		CDEBUG(D_ERROR, "Failed to allocate small rx descriptors\n");
		gmnal_free_txd(nal_data);
		GMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		return(-ENOMEM);
	}


	/*
 	 *	Hang out a bunch of small receive buffers
	 *	In fact hang them all out
	 */
	while((srxd = gmnal_get_srxd(nal_data, 0))) {
		CDEBUG(D_NET, "giving [%p] to gm_provide_recvive_buffer\n", 
		       srxd->buffer);
		GMNAL_GM_LOCK(nal_data);
		gm_provide_receive_buffer_with_tag(nal_data->gm_port, 
						   srxd->buffer, srxd->gmsize, 
						   GM_LOW_PRIORITY, 0);
		GMNAL_GM_UNLOCK(nal_data);
	}
	
	/*
	 *	Allocate pools of small tx buffers and descriptors
	 */
	if (gmnal_alloc_txd(nal_data) != GMNAL_STATUS_OK) {
		CDEBUG(D_ERROR, "Failed to allocate small tx descriptors\n");
		GMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		return(-ENOMEM);
	}

	gmnal_start_kernel_threads(nal_data);

	while (nal_data->rxthread_flag != GMNAL_RXTHREADS_STARTED) {
		gmnal_yield(1);
		CDEBUG(D_INFO, "Waiting for receive thread signs of life\n");
	}

	CDEBUG(D_INFO, "receive thread seems to have started\n");


	CDEBUG(D_NET, "Getting node id\n");
	GMNAL_GM_LOCK(nal_data);
	gm_status = gm_get_node_id(nal_data->gm_port, &local_nid);
	GMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		CDEBUG(D_ERROR, "can't determine node id\n");
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		GMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		return(-ENETDOWN);
	}

	nal_data->gm_local_nid = local_nid;
	CDEBUG(D_INFO, "Local node id is [%u]\n", local_nid);

	GMNAL_GM_LOCK(nal_data);
	gm_status = gm_node_id_to_global_id(nal_data->gm_port, local_nid, 
					    &global_nid);
	GMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		CDEBUG(D_ERROR, "failed to obtain global id\n");
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		GMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		return(-ENETDOWN);
	}
	CDEBUG(D_INFO, "Global node id is [%u]\n", global_nid);
	nal_data->gm_global_nid = global_nid;
        snprintf(global_nid_str, GLOBAL_NID_STR_LEN, "%u", global_nid);

/*
	pid = gm_getpid();
*/
        ni->ni_nid = global_nid;

	CDEBUG(D_INFO, "portals_pid is [%u]\n", ni->ni_pid);
	CDEBUG(D_INFO, "portals_nid is ["LPU64"]\n", ni->ni_nid);
	
        /* might be better to initialise this at module load rather than in
         * NAL startup */
        nal_data->sysctl = NULL;
        nal_data->sysctl = register_sysctl_table (gmnalnal_top_sysctl_table, 0);

	CDEBUG(D_INFO, "finished\n");

	global_nal_data = nal_data;

        PORTAL_MODULE_USE;
	return(0);
}

ptl_nal_t the_gm_nal = {
        .nal_type           = GMNAL,
        .nal_startup        = gmnal_startup,
        .nal_shutdown       = gmnal_shutdown,
        .nal_cmd            = gmnal_ctl,
        .nal_send           = gmnal_cb_send,
        .nal_send_pages     = gmnal_cb_send_pages,
        .nal_recv           = gmnal_cb_recv,
        .nal_recv_pages     = gmnal_cb_recv_pages,
};

/* 
 *        Called when module loaded
 */
int gmnal_init(void)
{
        ptl_register_nal(&the_gm_nal);
        return (0);
}


/*
 *	Called when module removed
 */
void gmnal_fini()
{
	CDEBUG(D_TRACE, "gmnal_fini\n");

        ptl_unregister_nal(&the_gm_nal);
        LASSERT(global_nal_data == NULL);
}
