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

#include "lgmnal.h"

lgmnal_data_t	*global_nal_data = NULL;
/*
 *	lgmnal_api_forward
 *	This function takes a pack block of arguments from the NAL API
 *	module and passes them to the NAL CB module. The CB module unpacks
 *	the args and calls the appropriate function indicated by index.
 *	Typically this function is used to pass args between kernel and use
 *	space.
 *	As lgmanl exists entirely in kernel, just pass the arg block directly to
 *	the NAL CB, buy passing the args to lib_dispatch
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
lgmnal_api_forward(nal_t *nal, int index, void *args, size_t arg_len,
		void *ret, size_t ret_len)
{

	nal_cb_t	*nal_cb = NULL;
	lgmnal_data_t	*nal_data = NULL;




	CDEBUG(D_INFO, "lgmnal_api_forward: nal [%p], index [%d], args [%p], arglen [%u], ret [%p], retlen [%u]\n", nal, index, args, arg_len, ret, ret_len);

	if (!nal || !args || (index < 0) || (arg_len < 0)) {
			CDEBUG(D_ERROR, "Bad args to lgmnal_api_forward\n");
		return (PTL_FAIL);
	}

	if (ret && (ret_len <= 0)) {
		CDEBUG(D_ERROR, "Bad args to lgmnal_api_forward\n");
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
	
	CDEBUG(D_PORTALS, "lgmnal_api_forward calling lib_dispatch\n");
	lib_dispatch(nal_cb, NULL, index, args, ret);
	CDEBUG(D_PORTALS, "lgmnal_api_forward returns from lib_dispatch\n");

	return(PTL_OK);
}


/*
 *	lgmnal_api_shutdown
 *	Close down this interface and free any resources associated with it
 *	nal_t	nal	our nal to shutdown
 */
int
lgmnal_api_shutdown(nal_t *nal, int interface)
{

	lgmnal_data_t	*nal_data = nal->nal_data;

	CDEBUG(D_TRACE, "lgmnal_api_shutdown: nal_data [%p]\n", nal_data);

	return(PTL_OK);
}


/*
 *	lgmnal_api_validate
 *	validate a user address for use in communications
 *	There's nothing to be done here
 */
int
lgmnal_api_validate(nal_t *nal, void *base, size_t extent)
{

	CDEBUG(D_TRACE, "lgmnal_api_validate : nal [%p], base [%p], extent [%d]\n", nal, base, (int)extent);

	return(PTL_OK);
}



/*
 *	lgmnal_api_yield
 *	Give up the processor
 */
void
lgmnal_api_yield(nal_t *nal)
{
	CDEBUG(D_TRACE, "lgmnal_api_yield : nal [%p]\n", nal);

	set_current_state(TASK_INTERRUPTIBLE);
	schedule();

	return;
}



/*
 *	lgmnal_api_lock
 *	Take a threadsafe lock
 */
void
lgmnal_api_lock(nal_t *nal, unsigned long *flags)
{

	lgmnal_data_t	*nal_data;
	nal_cb_t	*nal_cb;
	CDEBUG(D_TRACE, "lgmnal_api_lock : nal [%p], flagsa [%p] flags[%lu]\n", nal, flags, *flags);

	nal_data = nal->nal_data;
	nal_cb = nal_data->nal_cb;

	nal_cb->cb_cli(nal_cb, flags);

	return;
}

/*
 *	lgmnal_api_unlock
 *	Release a threadsafe lock
 */
void
lgmnal_api_unlock(nal_t *nal, unsigned long *flags)
{
	lgmnal_data_t	*nal_data;
	nal_cb_t	*nal_cb;
	CDEBUG(D_TRACE, "lgmnal_api_lock : nal [%p], flags [%p]\n", nal, flags);

	nal_data = nal->nal_data;
	nal_cb = nal_data->nal_cb;

	nal_cb->cb_sti(nal_cb, flags);

	return;
}


nal_t *
lgmnal_init(int interface, ptl_pt_index_t ptl_size, ptl_ac_index_t ac_size, ptl_pid_t rpid)
{

	nal_t		*nal = NULL;
	nal_cb_t	*nal_cb = NULL;
	lgmnal_data_t	*nal_data = NULL;
	lgmnal_srxd_t	*srxd = NULL;
	gm_status_t	gm_status;
	unsigned int	local_nid = 0, global_nid = 0;
	ptl_nid_t	portals_nid;
	ptl_pid_t	portals_pid = 0;


	CDEBUG(D_TRACE, "lgmnal_init : interface [%d], ptl_size [%d], ac_size[%d]\n",
			interface, ptl_size, ac_size);

	if ((interface < 0) || (interface > LGMNAL_NUM_IF) || (ptl_size <= 0) || (ac_size <= 0) ) {
		CDEBUG(D_ERROR, "bad args\n");
		return(NULL);
	} else {
		CDEBUG(D_INFO, "parameters check out ok\n");
	}

	CDEBUG(D_INFO, "Acquired global lock\n");


	PORTAL_ALLOC(nal_data, sizeof(lgmnal_data_t));
	if (!nal_data) {
		CDEBUG(D_ERROR, "can't get memory\n");
		return(NULL);
	}	
	memset(nal_data, 0, sizeof(lgmnal_data_t));
	/*
 	 *	set the small message buffer size 
	 */
	nal_data->refcnt = 1;

	CDEBUG(D_INFO, "Allocd and reset nal_data[%p]\n", nal_data);
	CDEBUG(D_INFO, "small_msg_size is [%d]\n", nal_data->small_msg_size);

	PORTAL_ALLOC(nal, sizeof(nal_t));
	if (!nal) {
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));
		return(NULL);
	}
	memset(nal, 0, sizeof(nal_t));
	CDEBUG(D_INFO, "Allocd and reset nal[%p]\n", nal);

	PORTAL_ALLOC(nal_cb, sizeof(nal_cb_t));
	if (!nal_cb) {
		PORTAL_FREE(nal, sizeof(nal_t));
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));
		return(NULL);
	}
	memset(nal_cb, 0, sizeof(nal_cb_t));
	CDEBUG(D_INFO, "Allocd and reset nal_cb[%p]\n", nal_cb);

	LGMNAL_INIT_NAL(nal);
	LGMNAL_INIT_NAL_CB(nal_cb);
	/*
	 *	String them all together
	 */
	nal->nal_data = (void*)nal_data;
	nal_cb->nal_data = (void*)nal_data;
	nal_data->nal = nal;
	nal_data->nal_cb = nal_cb;

	LGMNAL_CB_LOCK_INIT(nal_data);
	LGMNAL_GM_LOCK_INIT(nal_data);


	/*
 	 *	initialise the interface, 
	 */
	CDEBUG(D_INFO, "Calling gm_init\n");
	if (gm_init() != GM_SUCCESS) {
		CDEBUG(D_ERROR, "call to gm_init failed\n");
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
	}


	CDEBUG(D_NET, "Calling gm_open with interface [%d], port [%d], name [%s], version [%d]\n", interface, LGMNAL_GM_PORT, "lgmnal", GM_API_VERSION);

	LGMNAL_GM_LOCK(nal_data);
	gm_status = gm_open(&nal_data->gm_port, 0, LGMNAL_GM_PORT, "lgmnal", GM_API_VERSION);
	LGMNAL_GM_UNLOCK(nal_data);

	CDEBUG(D_INFO, "gm_open returned [%d]\n", gm_status);
	if (gm_status == GM_SUCCESS) {
		CDEBUG(D_INFO, "gm_open succeeded port[%p]\n", nal_data->gm_port);
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
			CDEBUG(D_ERROR, "gm_open Failure. Incompatile lib and driver\n");
			break;
		case(GM_OUT_OF_MEMORY):
			CDEBUG(D_ERROR, "gm_open Failure. Out of Memory\n");
			break;
		default:
			CDEBUG(D_ERROR, "gm_open Failure. Unknow error code [%d]\n", gm_status);
			break;
		}	
		LGMNAL_GM_LOCK(nal_data);
		gm_finalize();
		LGMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
	}

	
	nal_data->small_msg_size = lgmnal_small_msg_size;
	nal_data->small_msg_gmsize = gm_min_size_for_length(lgmnal_small_msg_size);

	if (lgmnal_alloc_srxd(nal_data) != LGMNAL_STATUS_OK) {
		CDEBUG(D_ERROR, "Failed to allocate small rx descriptors\n");
		lgmnal_free_stxd(nal_data);
		LGMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		LGMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
	}


	/*
 	 *	Hang out a bunch of small receive buffers
	 *	In fact hang them all out
	 */
	while((srxd = lgmnal_get_srxd(nal_data, 0))) {
		CDEBUG(D_NET, "giving [%p] to gm_provide_recvive_buffer\n", srxd->buffer);
		LGMNAL_GM_LOCK(nal_data);
		gm_provide_receive_buffer_with_tag(nal_data->gm_port, srxd->buffer, 
									srxd->gmsize, GM_LOW_PRIORITY, 0);
		LGMNAL_GM_UNLOCK(nal_data);
	}
	
	/*
	 *	Allocate pools of small tx buffers and descriptors
	 */
	if (lgmnal_alloc_stxd(nal_data) != LGMNAL_STATUS_OK) {
		CDEBUG(D_ERROR, "Failed to allocate small tx descriptors\n");
		LGMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		LGMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
	}

	/*
 	 *	Start the recieve thread
	 *	Initialise the gm_alarm we will use to wake the thread is 
	 *	it needs to be stopped
	 */
	CDEBUG(D_NET, "Initializing receive thread alarm and flag\n");
	gm_initialize_alarm(&nal_data->rxthread_alarm);
	nal_data->rxthread_flag = LGMNAL_THREAD_START;


	CDEBUG(D_INFO, "Starting receive thread\n");
	nal_data->rxthread_pid = kernel_thread(lgmnal_rx_thread, (void*)nal_data, 0);
	if (nal_data->rxthread_pid <= 0) {
		CDEBUG(D_ERROR, "Receive thread failed to start\n");
		lgmnal_free_stxd(nal_data);
		lgmnal_free_srxd(nal_data);
		LGMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		LGMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
	}
	while (nal_data->rxthread_flag != LGMNAL_THREAD_STARTED) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(128);
		CDEBUG(D_INFO, "Waiting for receive thread signs of life\n");
	}
	CDEBUG(D_INFO, "receive thread seems to have started\n");
	nal_data->rxthread_flag = LGMNAL_THREAD_CONTINUE;



	/*
	 *	Initialise the portals library
	 */
	CDEBUG(D_NET, "Getting node id\n");
	LGMNAL_GM_LOCK(nal_data);
	gm_status = gm_get_node_id(nal_data->gm_port, &local_nid);
	LGMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		lgmnal_stop_rxthread(nal_data);
		CDEBUG(D_ERROR, "can't determine node id\n");
		lgmnal_free_stxd(nal_data);
		lgmnal_free_srxd(nal_data);
		LGMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		LGMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
	}
	nal_data->gm_local_nid = local_nid;
	CDEBUG(D_INFO, "Local node id is [%u]\n", local_nid);
	LGMNAL_GM_LOCK(nal_data);
	gm_status = gm_node_id_to_global_id(nal_data->gm_port, local_nid, &global_nid);
	LGMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		CDEBUG(D_ERROR, "failed to obtain global id\n");
		lgmnal_stop_rxthread(nal_data);
		lgmnal_free_stxd(nal_data);
		lgmnal_free_srxd(nal_data);
		LGMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		LGMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
	}
	CDEBUG(D_INFO, "Global node id is [%u]\n", global_nid);
	nal_data->gm_global_nid = global_nid;

/*
	pid = gm_getpid();
*/
	CDEBUG(D_INFO, "portals_pid is [%u]\n", portals_pid);
	portals_nid = (unsigned long)global_nid;
	CDEBUG(D_INFO, "portals_nid is ["LPU64"]\n", portals_nid);
	
	CDEBUG(D_PORTALS, "calling lib_init\n");
	if (lib_init(nal_cb, portals_nid, portals_pid, 1024, ptl_size, ac_size) != PTL_OK) {
		CDEBUG(D_ERROR, "lib_init failed\n");
		lgmnal_stop_rxthread(nal_data);
		lgmnal_free_stxd(nal_data);
		lgmnal_free_srxd(nal_data);
		LGMNAL_GM_LOCK(nal_data);
		gm_close(nal_data->gm_port);
		gm_finalize();
		LGMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(nal, sizeof(nal_t));	
		PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
		PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
		return(NULL);
		
	}
	
	CDEBUG(D_INFO, "lgmnal_init finished\n");
	global_nal_data = nal->nal_data;
	return(nal);
}



/*
 *	Called when module removed
 */
void lgmnal_fini()
{
	lgmnal_data_t	*nal_data = global_nal_data;
	nal_t		*nal = nal_data->nal;
	nal_cb_t	*nal_cb = nal_data->nal_cb;

	CDEBUG(D_TRACE, "lgmnal_fini\n");

	PtlNIFini(lgmnal_ni);
	lib_fini(nal_cb);

	lgmnal_stop_rxthread(nal_data);
	lgmnal_free_stxd(nal_data);
	lgmnal_free_srxd(nal_data);
	LGMNAL_GM_LOCK(nal_data);
	gm_close(nal_data->gm_port);
	gm_finalize();
	LGMNAL_GM_UNLOCK(nal_data);
	PORTAL_FREE(nal, sizeof(nal_t));	
	PORTAL_FREE(nal_data, sizeof(lgmnal_data_t));	
	PORTAL_FREE(nal_cb, sizeof(nal_cb_t));
}

EXPORT_SYMBOL(lgmnal_init);
EXPORT_SYMBOL(lgmnal_fini);
EXPORT_SYMBOL(lgmnal_api_forward);
EXPORT_SYMBOL(lgmnal_api_validate);
EXPORT_SYMBOL(lgmnal_api_yield);
EXPORT_SYMBOL(lgmnal_api_lock);
EXPORT_SYMBOL(lgmnal_api_unlock);
EXPORT_SYMBOL(lgmnal_api_shutdown);
