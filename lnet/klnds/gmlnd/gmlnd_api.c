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
 *	gmnal_api_forward
 *	This function takes a pack block of arguments from the NAL API
 *	module and passes them to the NAL CB module. The CB module unpacks
 *	the args and calls the appropriate function indicated by index.
 *	Typically this function is used to pass args between kernel and use
 *	space.
 *	As lgmanl exists entirely in kernel, just pass the arg block directly 
 *	to the NAL CB, buy passing the args to lib_dispatch
 *	Arguments are
 *	nal_t	nal 	Our nal
 *	int	index	the api function that initiated this call 
 *	void 	*args	packed block of function args
 *	size_t	arg_len	length of args block
 *	void 	*ret	A return value for the API NAL
 *	size_t	ret_len	Size of the return value
 *	
 */

int
gmnal_api_forward(nal_t *nal, int index, void *args, size_t arg_len,
		void *ret, size_t ret_len)
{

	nal_cb_t	*nal_cb = NULL;
	gmnal_data_t	*nal_data = NULL;





	if (!nal || !args || (index < 0) || (arg_len < 0)) {
			CDEBUG(D_ERROR, "Bad args to gmnal_api_forward\n");
		return (PTL_FAIL);
	}

	if (ret && (ret_len <= 0)) {
		CDEBUG(D_ERROR, "Bad args to gmnal_api_forward\n");
		return (PTL_FAIL);
	}


	if (!nal->nal_data) {
		CDEBUG(D_ERROR, "bad nal, no nal data\n");	
		return (PTL_FAIL);
	}
	
	nal_data = nal->nal_data;
	CDEBUG(D_INFO, "nal_data is [%p]\n", nal_data);	

	if (!nal_data->nal_cb) {
		CDEBUG(D_ERROR, "bad nal_data, no nal_cb\n");	
		return (PTL_FAIL);
	}
	
	nal_cb = nal_data->nal_cb;
	CDEBUG(D_INFO, "nal_cb is [%p]\n", nal_cb);	
	
	CDEBUG(D_PORTALS, "gmnal_api_forward calling lib_dispatch\n");
	lib_dispatch(nal_cb, NULL, index, args, ret);
	CDEBUG(D_PORTALS, "gmnal_api_forward returns from lib_dispatch\n");

	return(PTL_OK);
}


/*
 *	gmnal_api_shutdown
 *      nal_refct == 0 => called on last matching PtlNIFini()
 *	Close down this interface and free any resources associated with it
 *	nal_t	nal	our nal to shutdown
 */
void
gmnal_api_shutdown(nal_t *nal, int interface)
{
	gmnal_data_t	*nal_data;
	nal_cb_t	*nal_cb;

        if (nal->nal_refct != 0)
                return;
        
	CDEBUG(D_TRACE, "gmnal_api_shutdown: nal_data [%p]\n", nal_data);

        LASSERT(nal == global_nal_data->nal);
        nal_data = nal->nal_data;
        LASSERT(nal_data == global_nal_data);
        nal_cb = nal_data->nal_cb;

        /* Stop portals calling our ioctl handler */
        libcfs_nal_cmd_unregister(GMNAL);

        /* XXX for shutdown "under fire" we probably need to set a shutdown
         * flag so when lib calls us we fail immediately and dont queue any
         * more work but our threads can still call into lib OK.  THEN
         * shutdown our threads, THEN lib_fini() */
        lib_fini(nal_cb);

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
	PORTAL_FREE(nal, sizeof(nal_t));	
	PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
	PORTAL_FREE(nal_cb, sizeof(nal_cb_t));

        global_nal_data = NULL;
        PORTAL_MODULE_UNUSE;
}


/*
 *	gmnal_api_validate
 *	validate a user address for use in communications
 *	There's nothing to be done here
 */
int
gmnal_api_validate(nal_t *nal, void *base, size_t extent)
{

	return(PTL_OK);
}



/*
 *	gmnal_api_yield
 *	Give up the processor
 */
void
gmnal_api_yield(nal_t *nal, unsigned long *flags, int milliseconds)
{
	CDEBUG(D_TRACE, "gmnal_api_yield : nal [%p]\n", nal);

        if (milliseconds != 0) {
                CERROR("Blocking yield not implemented yet\n");
                LBUG();
        }

        our_cond_resched();
	return;
}



/*
 *	gmnal_api_lock
 *	Take a threadsafe lock
 */
void
gmnal_api_lock(nal_t *nal, unsigned long *flags)
{

	gmnal_data_t	*nal_data;
	nal_cb_t	*nal_cb;

	nal_data = nal->nal_data;
	nal_cb = nal_data->nal_cb;

	nal_cb->cb_cli(nal_cb, flags);

	return;
}

/*
 *	gmnal_api_unlock
 *	Release a threadsafe lock
 */
void
gmnal_api_unlock(nal_t *nal, unsigned long *flags)
{
	gmnal_data_t	*nal_data;
	nal_cb_t	*nal_cb;

	nal_data = nal->nal_data;
	nal_cb = nal_data->nal_cb;

	nal_cb->cb_sti(nal_cb, flags);

	return;
}


int
gmnal_api_startup(nal_t *nal, ptl_pid_t requested_pid,
                  ptl_ni_limits_t *requested_limits,
                  ptl_ni_limits_t *actual_limits)
{

	nal_cb_t	*nal_cb = NULL;
	gmnal_data_t	*nal_data = NULL;
	gmnal_srxd_t	*srxd = NULL;
	gm_status_t	gm_status;
	unsigned int	local_nid = 0, global_nid = 0;
        ptl_process_id_t process_id;

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL) {
                        nal_data = (gmnal_data_t *)nal->nal_data;
                        nal_cb = nal_data->nal_cb;
                        *actual_limits = nal->_cb->ni.actual_limits;
                return (PTL_OK);
        }

        /* Called on first PtlNIInit() */

	CDEBUG(D_TRACE, "startup\n");

        LASSERT(global_nal_data == NULL);

	PORTAL_ALLOC(nal_data, sizeof(gmnal_data_t));
	if (!nal_data) {
		CDEBUG(D_ERROR, "can't get memory\n");
		return(PTL_NO_SPACE);
	}	
	memset(nal_data, 0, sizeof(gmnal_data_t));
	/*
 	 *	set the small message buffer size 
	 */

	CDEBUG(D_INFO, "Allocd and reset nal_data[%p]\n", nal_data);
	CDEBUG(D_INFO, "small_msg_size is [%d]\n", nal_data->small_msg_size);

	PORTAL_ALLOC(nal_cb, sizeof(nal_cb_t));
	if (!nal_cb) {
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));
		return(PTL_NO_SPACE);
	}
	memset(nal_cb, 0, sizeof(nal_cb_t));
	CDEBUG(D_INFO, "Allocd and reset nal_cb[%p]\n", nal_cb);

	GMNAL_INIT_NAL_CB(nal_cb);
	/*
	 *	String them all together
	 */
	nal->nal_data = (void*)nal_data;
	nal_cb->nal_data = (void*)nal_data;
	nal_data->nal = nal;
	nal_data->nal_cb = nal_cb;

	GMNAL_CB_LOCK_INIT(nal_data);
	GMNAL_GM_LOCK_INIT(nal_data);


	/*
 	 *	initialise the interface, 
	 */
	CDEBUG(D_INFO, "Calling gm_init\n");
	if (gm_init() != GM_SUCCESS) {
		CDEBUG(D_ERROR, "call to gm_init failed\n");
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
	}


	CDEBUG(D_NET, "Calling gm_open with interface [%d], port [%d], "
       	       "name [%s], version [%d]\n", interface, GMNAL_GM_PORT, 
	       "gmnal", GM_API_VERSION);

	GMNAL_GM_LOCK(nal_data);
	gm_status = gm_open(&nal_data->gm_port, 0, GMNAL_GM_PORT, "gmnal", 
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
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
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
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
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
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
	}

	gmnal_start_kernel_threads(nal_data);

	while (nal_data->rxthread_flag != GMNAL_RXTHREADS_STARTED) {
		gmnal_yield(1);
		CDEBUG(D_INFO, "Waiting for receive thread signs of life\n");
	}

	CDEBUG(D_INFO, "receive thread seems to have started\n");


	/*
	 *	Initialise the portals library
	 */
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
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
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
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
	}
	CDEBUG(D_INFO, "Global node id is [%u]\n", global_nid);
	nal_data->gm_global_nid = global_nid;
        snprintf(global_nid_str, GLOBAL_NID_STR_LEN, "%u", global_nid);

/*
	pid = gm_getpid();
*/
        process_id.pid = 0;
        process_id.nid = global_nid;
        
	CDEBUG(D_INFO, "portals_pid is [%u]\n", process_id.pid);
	CDEBUG(D_INFO, "portals_nid is ["LPU64"]\n", process_id.nid);
	
	CDEBUG(D_PORTALS, "calling lib_init\n");
	if (lib_init(nal_cb, process_id, 
                     requested_limits, actual_limits) != PTL_OK) {
		CDEBUG(D_ERROR, "lib_init failed\n");
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		GMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
		
	}

	if (libcfs_nal_cmd_register(GMNAL, &gmnal_cmd, nal->nal_data) != 0) {
		CDEBUG(D_INFO, "libcfs_nal_cmd_register failed\n");

                /* XXX these cleanup cases should be restructured to
                 * minimise duplication... */
                lib_fini(nal_cb);
                
		gmnal_stop_rxthread(nal_data);
		gmnal_stop_ctthread(nal_data);
		gmnal_free_txd(nal_data);
		gmnal_free_srxd(nal_data);
		GMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal_data, sizeof(gmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(PTL_FAIL);
        }

        /* might be better to initialise this at module load rather than in
         * NAL startup */
        nal_data->sysctl = NULL;
        nal_data->sysctl = register_sysctl_table (gmnalnal_top_sysctl_table, 0);

	
	CDEBUG(D_INFO, "gmnal_init finished\n");
	global_nal_data = nal->nal_data;

        /* no unload now until shutdown */
        PORTAL_MODULE_USE;
        
	return(PTL_OK);
}

nal_t the_gm_nal;

/* 
 *        Called when module loaded
 */
int gmnal_init(void)
{
        int    rc;

	memset(&the_gm_nal, 0, sizeof(nal_t));
	CDEBUG(D_INFO, "reset nal[%p]\n", &the_gm_nal);
	GMNAL_INIT_NAL(&the_gm_nal);

        rc = ptl_register_nal(GMNAL, &the_gm_nal);
        if (rc != PTL_OK)
                CERROR("Can't register GMNAL: %d\n", rc);

        return (rc);
}

                

/*
 *	Called when module removed
 */
void gmnal_fini()
{
	gmnal_data_t	*nal_data = global_nal_data;
	nal_t		*nal = nal_data->nal;
	nal_cb_t	*nal_cb = nal_data->nal_cb;

	CDEBUG(D_TRACE, "gmnal_fini\n");

        LASSERT(global_nal_data == NULL);

        ptl_unregister_nal(GMNAL);
}
