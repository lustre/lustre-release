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
 *	This file contains all gmnal send and receive functions
 */

#include "gmnal.h"

/*
 *	The caretaker thread
 *	This is main thread of execution for the NAL side
 *	This guy waits in gm_blocking_recvive and gets
 *	woken up when the myrinet adaptor gets an interrupt.
 *	Hands off receive operations to the receive thread 
 *	This thread Looks after gm_callbacks etc inline.
 */
int
gmnal_ct_thread(void *arg)
{
	gmnal_data_t		*nal_data;
	gm_recv_event_t		*rxevent = NULL;
	gm_recv_t		*recv = NULL;

	if (!arg) {
		CDEBUG(D_TRACE, "NO nal_data. Exiting\n");
		return(-1);
	}

	nal_data = (gmnal_data_t*)arg;
	CDEBUG(D_TRACE, "nal_data is [%p]\n", arg);

	daemonize();

	nal_data->ctthread_flag = GMNAL_CTTHREAD_STARTED;

	GMNAL_GM_LOCK(nal_data);
	while(nal_data->ctthread_flag == GMNAL_CTTHREAD_STARTED) {
		CDEBUG(D_NET, "waiting\n");
		rxevent = gm_blocking_receive_no_spin(nal_data->gm_port);
		if (nal_data->ctthread_flag == GMNAL_THREAD_STOP) {
			CDEBUG(D_INFO, "time to exit\n");
			break;
		}
		CDEBUG(D_INFO, "got [%s]\n", gmnal_rxevent(rxevent));
		switch (GM_RECV_EVENT_TYPE(rxevent)) {

			case(GM_RECV_EVENT):
				CDEBUG(D_NET, "CTTHREAD:: GM_RECV_EVENT\n");
				recv = (gm_recv_t*)&rxevent->recv;
				GMNAL_GM_UNLOCK(nal_data);
				gmnal_add_rxtwe(nal_data, recv);
				GMNAL_GM_LOCK(nal_data);
				CDEBUG(D_NET, "CTTHREAD:: Added event to Q\n");
			break;
			case(_GM_SLEEP_EVENT):
				/*
				 *	Blocking receive above just returns
				 *	immediatly with _GM_SLEEP_EVENT
				 *	Don't know what this is
				 */
				CDEBUG(D_NET, "Sleeping in gm_unknown\n");
				GMNAL_GM_UNLOCK(nal_data);
				gm_unknown(nal_data->gm_port, rxevent);
				GMNAL_GM_LOCK(nal_data);
				CDEBUG(D_INFO, "Awake from gm_unknown\n");
				break;
				
			default:
				/*
				 *	Don't know what this is
				 *	gm_unknown will make sense of it
				 *	Should be able to do something with
				 *	FAST_RECV_EVENTS here.
				 */
				CDEBUG(D_NET, "Passing event to gm_unknown\n");
				GMNAL_GM_UNLOCK(nal_data);
				gm_unknown(nal_data->gm_port, rxevent);
				GMNAL_GM_LOCK(nal_data);
				CDEBUG(D_INFO, "Processed unknown event\n");
		}
	}
	GMNAL_GM_UNLOCK(nal_data);
	nal_data->ctthread_flag = GMNAL_THREAD_RESET;
	CDEBUG(D_INFO, "thread nal_data [%p] is exiting\n", nal_data);
	return(GMNAL_STATUS_OK);
}


/*
 *	process a receive event
 */
int gmnal_rx_thread(void *arg)
{
	gmnal_data_t		*nal_data;
	void			*buffer;
	gmnal_rxtwe_t		*we = NULL;

	if (!arg) {
		CDEBUG(D_TRACE, "NO nal_data. Exiting\n");
		return(-1);
	}

	nal_data = (gmnal_data_t*)arg;
	CDEBUG(D_TRACE, "nal_data is [%p]\n", arg);

	daemonize();
	/*
	 * 	set 1 bit for each thread started
	 *	doesn't matter which bit
	 */
	spin_lock(&nal_data->rxthread_flag_lock);
	if (nal_data->rxthread_flag)
		nal_data->rxthread_flag=nal_data->rxthread_flag*2 + 1;
	else
		nal_data->rxthread_flag = 1;
	CDEBUG(D_INFO, "rxthread flag is [%ld]\n", nal_data->rxthread_flag);
	spin_unlock(&nal_data->rxthread_flag_lock);

	while(nal_data->rxthread_stop_flag != GMNAL_THREAD_STOP) {
		CDEBUG(D_NET, "RXTHREAD:: Receive thread waiting\n");
		we = gmnal_get_rxtwe(nal_data);
		if (!we) {
			CDEBUG(D_INFO, "Receive thread time to exit\n");
			break;
		}

		buffer = we->buffer;
		switch(((gmnal_msghdr_t*)buffer)->type) {
		case(GMNAL_SMALL_MESSAGE):
			gmnal_pre_receive(nal_data, we, 
					   GMNAL_SMALL_MESSAGE);
		break;	
		case(GMNAL_LARGE_MESSAGE_INIT):
			gmnal_pre_receive(nal_data, we, 
					   GMNAL_LARGE_MESSAGE_INIT);
		break;	
		case(GMNAL_LARGE_MESSAGE_ACK):
			gmnal_pre_receive(nal_data, we, 
					   GMNAL_LARGE_MESSAGE_ACK);
		break;	
		default:
			CDEBUG(D_ERROR, "Unsupported message type\n");
			gmnal_rx_bad(nal_data, we, NULL);
		}
		PORTAL_FREE(we, sizeof(gmnal_rxtwe_t));
	}

	spin_lock(&nal_data->rxthread_flag_lock);
	nal_data->rxthread_flag/=2;
	CDEBUG(D_INFO, "rxthread flag is [%ld]\n", nal_data->rxthread_flag);
	spin_unlock(&nal_data->rxthread_flag_lock);
	CDEBUG(D_INFO, "thread nal_data [%p] is exiting\n", nal_data);
	return(GMNAL_STATUS_OK);
}



/*
 *	Start processing a small message receive
 *	Get here from gmnal_receive_thread
 *	Hand off to lib_parse, which calls cb_recv
 *	which hands back to gmnal_small_receive
 *	Deal with all endian stuff here.
 */
int
gmnal_pre_receive(gmnal_data_t *nal_data, gmnal_rxtwe_t *we, int gmnal_type)
{
	gmnal_srxd_t	*srxd = NULL;
	void		*buffer = NULL;
	unsigned int snode, sport, type, length;
	gmnal_msghdr_t	*gmnal_msghdr;
	ptl_hdr_t	*portals_hdr;

	CDEBUG(D_INFO, "nal_data [%p], we[%p] type [%d]\n", 
	       nal_data, we, gmnal_type);

	buffer = we->buffer;
	snode = we->snode;
	sport = we->sport;
	type = we->type;
	buffer = we->buffer;
	length = we->length;

	gmnal_msghdr = (gmnal_msghdr_t*)buffer;
	portals_hdr = (ptl_hdr_t*)(buffer+GMNAL_MSGHDR_SIZE);

	CDEBUG(D_INFO, "rx_event:: Sender node [%d], Sender Port [%d], 
	       type [%d], length [%d], buffer [%p]\n",
	       snode, sport, type, length, buffer);
	CDEBUG(D_INFO, "gmnal_msghdr:: Sender node [%u], magic [%d], 
	       gmnal_type [%d]\n", gmnal_msghdr->sender_node_id, 
	       gmnal_msghdr->magic, gmnal_msghdr->type);
	CDEBUG(D_INFO, "portals_hdr:: Sender node ["LPD64"], 
	       dest_node ["LPD64"]\n", portals_hdr->src_nid, 
	       portals_hdr->dest_nid);

	
	/*
 	 *	Get a receive descriptor for this message
	 */
	srxd = gmnal_rxbuffer_to_srxd(nal_data, buffer);
	CDEBUG(D_INFO, "Back from gmnal_rxbuffer_to_srxd\n");
	srxd->nal_data = nal_data;
	if (!srxd) {
		CDEBUG(D_ERROR, "Failed to get receive descriptor\n");
		lib_parse(nal_data->nal_cb, portals_hdr, srxd);
		return(GMNAL_STATUS_FAIL);
	}

	/*
 	 *	no need to bother portals library with this
	 */
	if (gmnal_type == GMNAL_LARGE_MESSAGE_ACK) {
		gmnal_large_tx_ack_received(nal_data, srxd);
		return(GMNAL_STATUS_OK);
	}

	srxd->type = gmnal_type;
	srxd->nsiov = gmnal_msghdr->niov;
	srxd->gm_source_node = gmnal_msghdr->sender_node_id;
	
	CDEBUG(D_PORTALS, "Calling lib_parse buffer is [%p]\n", 
	       buffer+GMNAL_MSGHDR_SIZE);
	/*
 	 *	control passes to lib, which calls cb_recv 
	 *	cb_recv is responsible for returning the buffer 
	 *	for future receive
	 */
	lib_parse(nal_data->nal_cb, portals_hdr, srxd);

	return(GMNAL_STATUS_OK);
}



/*
 *	After a receive has been processed, 
 *	hang out the receive buffer again.
 *	This implicitly returns a receive token.
 */
int
gmnal_rx_requeue_buffer(gmnal_data_t *nal_data, gmnal_srxd_t *srxd)
{
	CDEBUG(D_TRACE, "gmnal_rx_requeue_buffer\n");

	CDEBUG(D_NET, "requeueing srxd[%p] nal_data[%p]\n", srxd, nal_data);

	GMNAL_GM_LOCK(nal_data);
	gm_provide_receive_buffer_with_tag(nal_data->gm_port, srxd->buffer,
					srxd->gmsize, GM_LOW_PRIORITY, 0 );
	GMNAL_GM_UNLOCK(nal_data);

	return(GMNAL_STATUS_OK);
}


/*
 *	Handle a bad message
 *	A bad message is one we don't expect or can't interpret
 */
int
gmnal_rx_bad(gmnal_data_t *nal_data, gmnal_rxtwe_t *we, gmnal_srxd_t *srxd)
{
	CDEBUG(D_TRACE, "Can't handle message\n");

	if (!srxd)
		srxd = gmnal_rxbuffer_to_srxd(nal_data, 
					       we->buffer);
	if (srxd) {
		gmnal_rx_requeue_buffer(nal_data, srxd);
	} else {
		CDEBUG(D_ERROR, "Can't find a descriptor for this buffer\n");
		/*
		 *	get rid of it ?
		 */
		return(GMNAL_STATUS_FAIL);
	}

	return(GMNAL_STATUS_OK);
}



/*
 *	Process a small message receive.
 *	Get here from gmnal_receive_thread, gmnal_pre_receive
 *	lib_parse, cb_recv
 *	Put data from prewired receive buffer into users buffer(s)
 *	Hang out the receive buffer again for another receive
 *	Call lib_finalize
 */
int
gmnal_small_rx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, 
		unsigned int niov, struct iovec *iov, size_t mlen, size_t rlen)
{
	gmnal_srxd_t	*srxd = NULL;
	void	*buffer = NULL;
	gmnal_data_t	*nal_data = (gmnal_data_t*)nal_cb->nal_data;


	CDEBUG(D_TRACE, "niov [%d] mlen["LPSZ"]\n", niov, mlen);

	if (!private) {
		CDEBUG(D_ERROR, "gmnal_small_rx no context\n");
		lib_finalize(nal_cb, private, cookie);
		return(PTL_FAIL);
	}

	srxd = (gmnal_srxd_t*)private;
	buffer = srxd->buffer;
	buffer += sizeof(gmnal_msghdr_t);
	buffer += sizeof(ptl_hdr_t);

	while(niov--) {
		CDEBUG(D_INFO, "processing [%p] len ["LPSZ"]\n", iov, 
		       iov->iov_len);
		gm_bcopy(buffer, iov->iov_base, iov->iov_len);			
		buffer += iov->iov_len;
		iov++;
	}


	/*
 	 *	let portals library know receive is complete
	 */
	CDEBUG(D_PORTALS, "calling lib_finalize\n");
	if (lib_finalize(nal_cb, private, cookie) != PTL_OK) {
		/* TO DO what to do with failed lib_finalise? */
		CDEBUG(D_INFO, "lib_finalize failed\n");
	}
	/*
	 *	return buffer so it can be used again
	 */
	CDEBUG(D_NET, "calling gm_provide_receive_buffer\n");
	GMNAL_GM_LOCK(nal_data);
	gm_provide_receive_buffer_with_tag(nal_data->gm_port, srxd->buffer, 
					   srxd->gmsize, GM_LOW_PRIORITY, 0);	
	GMNAL_GM_UNLOCK(nal_data);

	return(PTL_OK);
}


/*
 *	Start a small transmit. 
 *	Get a send token (and wired transmit buffer).
 *	Copy data from senders buffer to wired buffer and
 *	initiate gm_send from the wired buffer.
 *	The callback function informs when the send is complete.
 */
int
gmnal_small_tx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, 
		ptl_hdr_t *hdr, int type, ptl_nid_t global_nid, ptl_pid_t pid, 
		unsigned int niov, struct iovec *iov, int size)
{
	gmnal_data_t	*nal_data = (gmnal_data_t*)nal_cb->nal_data;
	gmnal_stxd_t	*stxd = NULL;
	void		*buffer = NULL;
	gmnal_msghdr_t	*msghdr = NULL;
	int		tot_size = 0;
	unsigned int	local_nid;
	gm_status_t	gm_status = GM_SUCCESS;

	CDEBUG(D_TRACE, "gmnal_small_tx nal_cb [%p] private [%p] cookie [%p] 
	       hdr [%p] type [%d] global_nid ["LPU64"] pid [%d] niov [%d] 
	       iov [%p] size [%d]\n", nal_cb, private, cookie, hdr, type, 
	       global_nid, pid, niov, iov, size);

	CDEBUG(D_INFO, "portals_hdr:: dest_nid ["LPU64"], src_nid ["LPU64"]\n",
	       hdr->dest_nid, hdr->src_nid);

	if (!nal_data) {
		CDEBUG(D_ERROR, "no nal_data\n");
		return(GMNAL_STATUS_FAIL);
	} else {
		CDEBUG(D_INFO, "nal_data [%p]\n", nal_data);
	}

	GMNAL_GM_LOCK(nal_data);
	gm_status = gm_global_id_to_node_id(nal_data->gm_port, global_nid, 
					    &local_nid);
	GMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		CDEBUG(D_ERROR, "Failed to obtain local id\n");
		return(GMNAL_STATUS_FAIL);
	}
	CDEBUG(D_INFO, "Local Node_id is [%u][%x]\n", local_nid, local_nid);

	stxd = gmnal_get_stxd(nal_data, 1);
	CDEBUG(D_INFO, "stxd [%p]\n", stxd);

	stxd->type = GMNAL_SMALL_MESSAGE;
	stxd->cookie = cookie;

	/*
	 *	Copy gmnal_msg_hdr and portals header to the transmit buffer
	 *	Then copy the data in
	 */
	buffer = stxd->buffer;
	msghdr = (gmnal_msghdr_t*)buffer;

	msghdr->magic = GMNAL_MAGIC;
	msghdr->type = GMNAL_SMALL_MESSAGE;
	msghdr->sender_node_id = nal_data->gm_global_nid;
	CDEBUG(D_INFO, "processing msghdr at [%p]\n", buffer);

	buffer += sizeof(gmnal_msghdr_t);

	CDEBUG(D_INFO, "processing  portals hdr at [%p]\n", buffer);
	gm_bcopy(hdr, buffer, sizeof(ptl_hdr_t));

	buffer += sizeof(ptl_hdr_t);

	while(niov--) {
		CDEBUG(D_INFO, "processing iov [%p] len ["LPSZ"] to [%p]\n", 
		       iov, iov->iov_len, buffer);
		gm_bcopy(iov->iov_base, buffer, iov->iov_len);
		buffer+= iov->iov_len;
		iov++;
	}

	CDEBUG(D_INFO, "sending\n");
	tot_size = size+sizeof(ptl_hdr_t)+sizeof(gmnal_msghdr_t);
	stxd->msg_size = tot_size;


	CDEBUG(D_NET, "Calling gm_send_to_peer port [%p] buffer [%p] 
   	       gmsize [%lu] msize [%d] global_nid ["LPU64"] local_nid[%d] 
	       stxd [%p]\n", nal_data->gm_port, stxd->buffer, stxd->gm_size, 
	       stxd->msg_size, global_nid, local_nid, stxd);

	GMNAL_GM_LOCK(nal_data);
	stxd->gm_priority = GM_LOW_PRIORITY;
	stxd->gm_target_node = local_nid;
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, 
				      stxd->gm_size, stxd->msg_size, 
				      GM_LOW_PRIORITY, local_nid, 
				      gmnal_small_tx_callback, (void*)stxd);
	GMNAL_GM_UNLOCK(nal_data);
	CDEBUG(D_INFO, "done\n");
		
	return(PTL_OK);
}


/*
 *	A callback to indicate the small transmit operation is compete
 *	Check for erros and try to deal with them.
 *	Call lib_finalise to inform the client application that the send 
 *	is complete and the memory can be reused.
 *	Return the stxd when finished with it (returns a send token)
 */
void 
gmnal_small_tx_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{
	gmnal_stxd_t	*stxd = (gmnal_stxd_t*)context;
	lib_msg_t	*cookie = stxd->cookie;
	gmnal_data_t	*nal_data = (gmnal_data_t*)stxd->nal_data;
	nal_cb_t	*nal_cb = nal_data->nal_cb;

	if (!stxd) {
		CDEBUG(D_TRACE, "send completion event for unknown stxd\n");
		return;
	}
	if (status != GM_SUCCESS) {
		CDEBUG(D_ERROR, "Result of send stxd [%p] is [%s]\n", 
		       stxd, gmnal_gm_error(status));
	}

	switch(status) {
  		case(GM_SUCCESS):
		break;



  		case(GM_SEND_DROPPED):
		/*
		 *	do a resend on the dropped ones
		 */
			CDEBUG(D_ERROR, "send stxd [%p] was dropped 
			       resending\n", context);
			GMNAL_GM_LOCK(nal_data);
			gm_send_to_peer_with_callback(nal_data->gm_port, 
						      stxd->buffer, 
						      stxd->gm_size, 
						      stxd->msg_size, 
						      stxd->gm_priority, 
						      stxd->gm_target_node, 
						      gmnal_small_tx_callback,
						      context);
			GMNAL_GM_UNLOCK(nal_data);
		
		return;
  		case(GM_TIMED_OUT):
  		case(GM_SEND_TIMED_OUT):
		/*
		 *	drop these ones
		 */
			CDEBUG(D_INFO, "calling gm_drop_sends\n");
			GMNAL_GM_LOCK(nal_data);
			gm_drop_sends(nal_data->gm_port, stxd->gm_priority, 
				      stxd->gm_target_node, GMNAL_GM_PORT, 
				      gmnal_drop_sends_callback, context);
			GMNAL_GM_UNLOCK(nal_data);

		return;


		/*
		 *	abort on these ?
		 */
  		case(GM_TRY_AGAIN):
  		case(GM_INTERRUPTED):
  		case(GM_FAILURE):
  		case(GM_INPUT_BUFFER_TOO_SMALL):
  		case(GM_OUTPUT_BUFFER_TOO_SMALL):
  		case(GM_BUSY):
  		case(GM_MEMORY_FAULT):
  		case(GM_INVALID_PARAMETER):
  		case(GM_OUT_OF_MEMORY):
  		case(GM_INVALID_COMMAND):
  		case(GM_PERMISSION_DENIED):
  		case(GM_INTERNAL_ERROR):
  		case(GM_UNATTACHED):
  		case(GM_UNSUPPORTED_DEVICE):
  		case(GM_SEND_REJECTED):
  		case(GM_SEND_TARGET_PORT_CLOSED):
  		case(GM_SEND_TARGET_NODE_UNREACHABLE):
  		case(GM_SEND_PORT_CLOSED):
  		case(GM_NODE_ID_NOT_YET_SET):
  		case(GM_STILL_SHUTTING_DOWN):
  		case(GM_CLONE_BUSY):
  		case(GM_NO_SUCH_DEVICE):
  		case(GM_ABORTED):
  		case(GM_INCOMPATIBLE_LIB_AND_DRIVER):
  		case(GM_UNTRANSLATED_SYSTEM_ERROR):
  		case(GM_ACCESS_DENIED):
  		case(GM_NO_DRIVER_SUPPORT):
  		case(GM_PTE_REF_CNT_OVERFLOW):
  		case(GM_NOT_SUPPORTED_IN_KERNEL):
  		case(GM_NOT_SUPPORTED_ON_ARCH):
  		case(GM_NO_MATCH):
  		case(GM_USER_ERROR):
  		case(GM_DATA_CORRUPTED):
  		case(GM_HARDWARE_FAULT):
  		case(GM_SEND_ORPHANED):
  		case(GM_MINOR_OVERFLOW):
  		case(GM_PAGE_TABLE_FULL):
  		case(GM_UC_ERROR):
  		case(GM_INVALID_PORT_NUMBER):
  		case(GM_DEV_NOT_FOUND):
  		case(GM_FIRMWARE_NOT_RUNNING):
  		case(GM_YP_NO_MATCH):
		default:
			CDEBUG(D_ERROR, "Unknown send error\n");
	}

	/*
	 *	TO DO
	 *	If this is a large message init,
	 *	we're not finished with the data yet,
	 *	so can't call lib_finalise.
	 *	However, we're also holding on to a 
	 *	stxd here (to keep track of the source
	 *	iovec only). Should use another structure
	 *	to keep track of iovec and return stxd to 
	 *	free list earlier.
	 */
	if (stxd->type == GMNAL_LARGE_MESSAGE_INIT) {
		CDEBUG(D_INFO, "large transmit done\n");
		return;
	}
	gmnal_return_stxd(nal_data, stxd);
	if (lib_finalize(nal_cb, stxd, cookie) != PTL_OK) {
		CDEBUG(D_INFO, "Call to lib_finalize failed for stxd [%p]\n", 
		       stxd);
	}
	return;
}



void gmnal_drop_sends_callback(struct gm_port *gm_port, void *context, 
			        gm_status_t status)
{
	gmnal_stxd_t	*stxd = (gmnal_stxd_t*)context;
	gmnal_data_t	*nal_data = stxd->nal_data;

	CDEBUG(D_TRACE, "status is [%d] context is [%p]\n", status, context);
	if (status == GM_SUCCESS) {
		GMNAL_GM_LOCK(nal_data);
		gm_send_to_peer_with_callback(gm_port, stxd->buffer, 
					      stxd->gm_size, stxd->msg_size, 
					      stxd->gm_priority, 
					      stxd->gm_target_node, 
					      gmnal_small_tx_callback, 
					      context);
		GMNAL_GM_LOCK(nal_data);
	} else {
		CDEBUG(D_ERROR, "send_to_peer status for stxd [%p] is 
		       [%d][%s]\n", stxd, status, gmnal_gm_error(status));
	}


	return;
}


/*
 *	Begine a large transmit.
 *	Do a gm_register of the memory pointed to by the iovec 
 *	and send details to the receiver. The receiver does a gm_get
 *	to pull the data and sends and ack when finished. Upon receipt of
 *	this ack, deregister the memory. Only 1 send token is required here.
 */
int
gmnal_large_tx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, 
	        ptl_hdr_t *hdr, int type, ptl_nid_t global_nid, ptl_pid_t pid, 
		unsigned int niov, struct iovec *iov, int size)
{

	gmnal_data_t	*nal_data;
	gmnal_stxd_t	*stxd = NULL;
	void		*buffer = NULL;
	gmnal_msghdr_t	*msghdr = NULL;
	unsigned int	local_nid;
	int		mlen = 0;	/* the size of the init message data */
	struct iovec	*iov_dup = NULL;
	gm_status_t	gm_status;
	int		niov_dup;


	CDEBUG(D_TRACE, "gmnal_large_tx nal_cb [%p] private [%p], cookie [%p] 
	       hdr [%p], type [%d] global_nid ["LPU64"], pid [%d], niov [%d], 
	       iov [%p], size [%d]\n", nal_cb, private, cookie, hdr, type, 
	       global_nid, pid, niov, iov, size);

	if (nal_cb)
		nal_data = (gmnal_data_t*)nal_cb->nal_data;
	else  {
		CDEBUG(D_ERROR, "no nal_cb.\n");
		return(GMNAL_STATUS_FAIL);
	}
	

	/*
	 *	Get stxd and buffer. Put local address of data in buffer, 
	 *	send local addresses to target, 
	 *	wait for the target node to suck the data over.
	 *	The stxd is used to ren
	 */
	stxd = gmnal_get_stxd(nal_data, 1);
	CDEBUG(D_INFO, "stxd [%p]\n", stxd);

	stxd->type = GMNAL_LARGE_MESSAGE_INIT;
	stxd->cookie = cookie;

	/*
	 *	Copy gmnal_msg_hdr and portals header to the transmit buffer
	 *	Then copy the iov in
	 */
	buffer = stxd->buffer;
	msghdr = (gmnal_msghdr_t*)buffer;

	CDEBUG(D_INFO, "processing msghdr at [%p]\n", buffer);

	msghdr->magic = GMNAL_MAGIC;
	msghdr->type = GMNAL_LARGE_MESSAGE_INIT;
	msghdr->sender_node_id = nal_data->gm_global_nid;
	msghdr->stxd = stxd;
	msghdr->niov = niov ;
	buffer += sizeof(gmnal_msghdr_t);
	mlen = sizeof(gmnal_msghdr_t);
	CDEBUG(D_INFO, "mlen is [%d]\n", mlen);


	CDEBUG(D_INFO, "processing  portals hdr at [%p]\n", buffer);

	gm_bcopy(hdr, buffer, sizeof(ptl_hdr_t));
	buffer += sizeof(ptl_hdr_t);
	mlen += sizeof(ptl_hdr_t); 
	CDEBUG(D_INFO, "mlen is [%d]\n", mlen);

	/*
	 *	copy the iov to the buffer so target knows 
	 *	where to get the data from
	 */
	CDEBUG(D_INFO, "processing iov to [%p]\n", buffer);
	gm_bcopy(iov, buffer, niov*sizeof(struct iovec));
	mlen += niov*(sizeof(struct iovec));
	CDEBUG(D_INFO, "mlen is [%d]\n", mlen);


	/*
	 *	Store the iovs in the stxd for we can get 
	 *	them later if we need them
	 */
	CDEBUG(D_NET, "Copying iov [%p] to [%p]\n", iov, stxd->iov);
	gm_bcopy(iov, stxd->iov, niov*sizeof(struct iovec));
	stxd->niov = niov;
	

	/*
	 *	register the memory so the NIC can get hold of the data
	 *	This is a slow process. it'd be good to overlap it 
	 *	with something else.
	 */
	iov_dup = iov;
	niov_dup = niov;
	while(niov--) {
		CDEBUG(D_INFO, "Registering memory [%p] len ["LPSZ"] \n", 
		       iov->iov_base, iov->iov_len);
		GMNAL_GM_LOCK(nal_data);
		gm_status = gm_register_memory(nal_data->gm_port, 
					       iov->iov_base, iov->iov_len);
		if (gm_status != GM_SUCCESS) {
			GMNAL_GM_UNLOCK(nal_data);
			CDEBUG(D_ERROR, "gm_register_memory returns [%d][%s] 
			       for memory [%p] len ["LPSZ"]\n", 
			       gm_status, gmnal_gm_error(gm_status), 
			       iov->iov_base, iov->iov_len);
			GMNAL_GM_LOCK(nal_data);
			while (iov_dup != iov) {
				gm_deregister_memory(nal_data->gm_port, 
						     iov_dup->iov_base, 
						     iov_dup->iov_len);
				iov_dup++;
			}
			GMNAL_GM_UNLOCK(nal_data);
			gmnal_return_stxd(nal_data, stxd);
			return(PTL_FAIL);
		}

		GMNAL_GM_UNLOCK(nal_data);
		iov++;
	}

	/*
 	 *	Send the init message to the target
	 */
	CDEBUG(D_INFO, "sending mlen [%d]\n", mlen);
	GMNAL_GM_LOCK(nal_data);
	gm_status = gm_global_id_to_node_id(nal_data->gm_port, global_nid, 
					    &local_nid);
	if (gm_status != GM_SUCCESS) {
		GMNAL_GM_UNLOCK(nal_data);
		CDEBUG(D_ERROR, "Failed to obtain local id\n");
		gmnal_return_stxd(nal_data, stxd);
		/* TO DO deregister memory on failure */
		return(GMNAL_STATUS_FAIL);
	}
	CDEBUG(D_INFO, "Local Node_id is [%d]\n", local_nid);
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, 
				      stxd->gm_size, mlen, GM_LOW_PRIORITY, 
				      local_nid, gmnal_large_tx_callback, 
				      (void*)stxd);
	GMNAL_GM_UNLOCK(nal_data);
	
	CDEBUG(D_INFO, "done\n");
		
	return(PTL_OK);
}

/*
 *	Callback function indicates that send of buffer with 
 *	large message iovec has completed (or failed).
 */
void 
gmnal_large_tx_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{
	gmnal_small_tx_callback(gm_port, context, status);

}



/*
 *	Have received a buffer that contains an iovec of the sender. 
 *	Do a gm_register_memory of the receivers buffer and then do a get
 *	data from the sender.
 */
int
gmnal_large_rx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, 
		unsigned int nriov, struct iovec *riov, size_t mlen, 
		size_t rlen)
{
	gmnal_data_t	*nal_data = nal_cb->nal_data;
	gmnal_srxd_t	*srxd = (gmnal_srxd_t*)private;
	void		*buffer = NULL;
	struct	iovec	*riov_dup;
	int		nriov_dup;
	gmnal_msghdr_t	*msghdr = NULL;
	gm_status_t	gm_status;

	CDEBUG(D_TRACE, "gmnal_large_rx :: nal_cb[%p], private[%p], 
	       cookie[%p], niov[%d], iov[%p], mlen["LPSZ"], rlen["LPSZ"]\n",
		nal_cb, private, cookie, nriov, riov, mlen, rlen);

	if (!srxd) {
		CDEBUG(D_ERROR, "gmnal_large_rx no context\n");
		lib_finalize(nal_cb, private, cookie);
		return(PTL_FAIL);
	}

	buffer = srxd->buffer;
	msghdr = (gmnal_msghdr_t*)buffer;
	buffer += sizeof(gmnal_msghdr_t);
	buffer += sizeof(ptl_hdr_t);

	/*
	 *	Store the senders stxd address in the srxd for this message
	 *	The gmnal_large_message_ack needs it to notify the sender
	 *	the pull of data is complete
	 */
	srxd->source_stxd = msghdr->stxd;

	/*
	 *	Register the receivers memory
	 *	get the data,
	 *	tell the sender that we got the data
	 *	then tell the receiver we got the data
	 *	TO DO
	 *	If the iovecs match, could interleave 
	 *	gm_registers and gm_gets for each element
	 */
	nriov_dup = nriov;
	riov_dup = riov;
	while(nriov--) {
		CDEBUG(D_INFO, "Registering memory [%p] len ["LPSZ"] \n", 
		       riov->iov_base, riov->iov_len);
		GMNAL_GM_LOCK(nal_data);
		gm_status = gm_register_memory(nal_data->gm_port, 
					       riov->iov_base, riov->iov_len);
		if (gm_status != GM_SUCCESS) {
			GMNAL_GM_UNLOCK(nal_data);
			CDEBUG(D_ERROR, "gm_register_memory returns [%d][%s] 
			       for memory [%p] len ["LPSZ"]\n", 
			       gm_status, gmnal_gm_error(gm_status), 
			       riov->iov_base, riov->iov_len);
			GMNAL_GM_LOCK(nal_data);
			while (riov_dup != riov) {
				gm_deregister_memory(nal_data->gm_port, 
						     riov_dup->iov_base, 
						     riov_dup->iov_len);
				riov_dup++;
			}
			GMNAL_GM_LOCK(nal_data);
			/*
			 *	give back srxd and buffer. Send NACK to sender
			 */
			return(PTL_FAIL);
		}
		GMNAL_GM_UNLOCK(nal_data);
		riov++;
	}
	/*
	 *	do this so the final gm_get callback can deregister the memory
	 */
	PORTAL_ALLOC(srxd->riov, nriov_dup*(sizeof(struct iovec)));
	gm_bcopy(riov_dup, srxd->riov, nriov_dup*(sizeof(struct iovec)));
	srxd->nriov = nriov_dup;

	/*
	 *	now do gm_get to get the data
	 */
	srxd->cookie = cookie;
	if (gmnal_remote_get(srxd, srxd->nsiov, (struct iovec*)buffer, 
			      nriov_dup, riov_dup) != GMNAL_STATUS_OK) {
		CDEBUG(D_ERROR, "can't get the data");
	}

	CDEBUG(D_INFO, "lgmanl_large_rx done\n");

	return(PTL_OK);
}


/*
 *	Perform a number of remote gets as part of receiving 
 *	a large message.
 *	The final one to complete (i.e. the last callback to get called)
 *	tidies up.
 *	gm_get requires a send token.
 */
int
gmnal_remote_get(gmnal_srxd_t *srxd, int nsiov, struct iovec *siov, 
		  int nriov, struct iovec *riov)
{

	int	ncalls = 0;

	CDEBUG(D_TRACE, "gmnal_remote_get srxd[%p], nriov[%d], riov[%p], 
	       nsiov[%d], siov[%p]\n", srxd, nriov, riov, nsiov, siov);


	ncalls = gmnal_copyiov(0, srxd, nsiov, siov, nriov, riov);
	if (ncalls < 0) {
		CDEBUG(D_ERROR, "there's something wrong with the iovecs\n");
		return(GMNAL_STATUS_FAIL);
	}
	CDEBUG(D_INFO, "gmnal_remote_get ncalls [%d]\n", ncalls);
	spin_lock_init(&srxd->callback_lock);
	srxd->ncallbacks = ncalls;
	srxd->callback_status = 0;

	ncalls = gmnal_copyiov(1, srxd, nsiov, siov, nriov, riov);
	if (ncalls < 0) {
		CDEBUG(D_ERROR, "there's something wrong with the iovecs\n");
		return(GMNAL_STATUS_FAIL);
	}

	return(GMNAL_STATUS_OK);

}


/*
 *	pull data from source node (source iovec) to a local iovec.
 *	The iovecs may not match which adds the complications below.
 *	Count the number of gm_gets that will be required to the callbacks
 *	can determine who is the last one.
 */	
int
gmnal_copyiov(int do_copy, gmnal_srxd_t *srxd, int nsiov, 
	       struct iovec *siov, int nriov, struct iovec *riov)
{

	int	ncalls = 0;
	int	slen = siov->iov_len, rlen = riov->iov_len;
	char	*sbuf = siov->iov_base, *rbuf = riov->iov_base;	
	unsigned long	sbuf_long;
	gm_remote_ptr_t	remote_ptr = 0;
	unsigned int	source_node;
	gmnal_ltxd_t	*ltxd = NULL;
	gmnal_data_t	*nal_data = srxd->nal_data;

	CDEBUG(D_TRACE, "copy[%d] nal_data[%p]\n", do_copy, nal_data);
	if (do_copy) {
		if (!nal_data) {
			CDEBUG(D_ERROR, "Bad args No nal_data\n");
			return(GMNAL_STATUS_FAIL);
		}
		GMNAL_GM_LOCK(nal_data);
		if (gm_global_id_to_node_id(nal_data->gm_port, 
					    srxd->gm_source_node, 
					    &source_node) != GM_SUCCESS) {

			CDEBUG(D_ERROR, "cannot resolve global_id [%u] 
			       to local node_id\n", srxd->gm_source_node);
			GMNAL_GM_UNLOCK(nal_data);
			return(GMNAL_STATUS_FAIL);
		}
		GMNAL_GM_UNLOCK(nal_data);
		/*
		 *	We need a send token to use gm_get
		 *	getting an stxd gets us a send token.
		 *	the stxd is used as the context to the
	 	 *	callback function (so stxd can be returned).
		 *	Set pointer in stxd to srxd so callback count in srxd
		 *	can be decremented to find last callback to complete
		 */
		CDEBUG(D_INFO, "gmnal_copyiov source node is G[%u]L[%d]\n", 
		       srxd->gm_source_node, source_node);
	}

	do {
		CDEBUG(D_INFO, "sbuf[%p] slen[%d] rbuf[%p], rlen[%d]\n",
				sbuf, slen, rbuf, rlen);
		if (slen > rlen) {
			ncalls++;
			if (do_copy) {
				CDEBUG(D_INFO, "slen>rlen\n");
				ltxd = gmnal_get_ltxd(nal_data);
				ltxd->srxd = srxd;
				GMNAL_GM_LOCK(nal_data);
				/* 
				 *	funny business to get rid 
				 *	of compiler warning 
				 */
				sbuf_long = (unsigned long) sbuf;
				remote_ptr = (gm_remote_ptr_t)sbuf_long;
				gm_get(nal_data->gm_port, remote_ptr, rbuf, 
				       rlen, GM_LOW_PRIORITY, source_node, 
				       GMNAL_GM_PORT, 
				       gmnal_remote_get_callback, ltxd);
				GMNAL_GM_UNLOCK(nal_data);
			}
			/*
			 *	at the end of 1 iov element
		 	 */
			sbuf+=rlen;
			slen-=rlen;
			riov++;
			nriov--;
			rbuf = riov->iov_base;
			rlen = riov->iov_len;
		} else if (rlen > slen) {
			ncalls++;
			if (do_copy) {
				CDEBUG(D_INFO, "slen<rlen\n");
				ltxd = gmnal_get_ltxd(nal_data);
				ltxd->srxd = srxd;
				GMNAL_GM_LOCK(nal_data);
				sbuf_long = (unsigned long) sbuf;
				remote_ptr = (gm_remote_ptr_t)sbuf_long;
				gm_get(nal_data->gm_port, remote_ptr, rbuf, 
				       slen, GM_LOW_PRIORITY, source_node, 
				       GMNAL_GM_PORT, 
				       gmnal_remote_get_callback, ltxd);
				GMNAL_GM_UNLOCK(nal_data);
			}
			/*
			 *	at end of siov element
			 */
			rbuf+=slen;
			rlen-=slen;
			siov++;
			sbuf = siov->iov_base;
			slen = siov->iov_len;
		} else {
			ncalls++;
			if (do_copy) {
				CDEBUG(D_INFO, "rlen=slen\n");
				ltxd = gmnal_get_ltxd(nal_data);
				ltxd->srxd = srxd;
				GMNAL_GM_LOCK(nal_data);
				sbuf_long = (unsigned long) sbuf;
				remote_ptr = (gm_remote_ptr_t)sbuf_long;
				gm_get(nal_data->gm_port, remote_ptr, rbuf, 
				       rlen, GM_LOW_PRIORITY, source_node, 
				       GMNAL_GM_PORT, 
				       gmnal_remote_get_callback, ltxd);
				GMNAL_GM_UNLOCK(nal_data);
			}
			/*
			 *	at end of siov and riov element
			 */
			siov++;
			sbuf = siov->iov_base;
			slen = siov->iov_len;
			riov++;
			nriov--;
			rbuf = riov->iov_base;
			rlen = riov->iov_len;
		}

	} while (nriov);
	return(ncalls);
}


/*
 *	The callback function that is invoked after each gm_get call completes.
 *	Multiple callbacks may be invoked for 1 transaction, only the final
 *	callback has work to do.
 */
void
gmnal_remote_get_callback(gm_port_t *gm_port, void *context, 
			   gm_status_t status)
{

	gmnal_ltxd_t	*ltxd = (gmnal_ltxd_t*)context;
	gmnal_srxd_t	*srxd = ltxd->srxd;
	nal_cb_t	*nal_cb = srxd->nal_data->nal_cb;
	int		lastone;
	struct	iovec	*riov;
	int		nriov;
	gmnal_data_t	*nal_data;

	CDEBUG(D_TRACE, "called for context [%p]\n", context);

	if (status != GM_SUCCESS) {
		CDEBUG(D_ERROR, "reports error [%d][%s]\n", status, 
		       gmnal_gm_error(status));
	}

	spin_lock(&srxd->callback_lock);
	srxd->ncallbacks--;
	srxd->callback_status |= status;
	lastone = srxd->ncallbacks?0:1;
	spin_unlock(&srxd->callback_lock);
	nal_data = srxd->nal_data;

	/*
	 *	everyone returns a send token
	 */
	gmnal_return_ltxd(nal_data, ltxd);

	if (!lastone) {
		CDEBUG(D_ERROR, "NOT final callback context[%p]\n", srxd);
		return;
	}
	
	/*
	 *	Let our client application proceed
	 */	
	CDEBUG(D_ERROR, "final callback context[%p]\n", srxd);
	if (lib_finalize(nal_cb, srxd, srxd->cookie) != PTL_OK) {
		CDEBUG(D_INFO, "Call to lib_finalize failed for srxd [%p]\n", 
		       srxd);
	}

	/*
	 *	send an ack to the sender to let him know we got the data
	 */
	gmnal_large_tx_ack(nal_data, srxd);

	/*
	 *	Unregister the memory that was used
	 *	This is a very slow business (slower then register)
	 */
	nriov = srxd->nriov;
	riov = srxd->riov;
	GMNAL_GM_LOCK(nal_data);
	while (nriov--) {
		CDEBUG(D_ERROR, "deregister memory [%p]\n", riov->iov_base);
		if (gm_deregister_memory(srxd->nal_data->gm_port, 
		    		         riov->iov_base, riov->iov_len)) {
			CDEBUG(D_ERROR, "failed to deregister memory [%p]\n", 
			       riov->iov_base);
		}
		riov++;
	}
	GMNAL_GM_UNLOCK(nal_data);
	PORTAL_FREE(srxd->riov, sizeof(struct iovec)*nriov);

	/*
	 *	repost the receive buffer (return receive token)
	 */
	GMNAL_GM_LOCK(nal_data);
	gm_provide_receive_buffer_with_tag(nal_data->gm_port, srxd->buffer, 
					   srxd->gmsize, GM_LOW_PRIORITY, 0);	
	GMNAL_GM_UNLOCK(nal_data);
	
	return;
}


/*
 *	Called on target node.
 *	After pulling data from a source node
 *	send an ack message to indicate the large transmit is complete.
 */
void 
gmnal_large_tx_ack(gmnal_data_t *nal_data, gmnal_srxd_t *srxd)
{

	gmnal_stxd_t	*stxd;
	gmnal_msghdr_t *msghdr;
	void		*buffer = NULL;
	unsigned int	local_nid;
	gm_status_t	gm_status = GM_SUCCESS;

	CDEBUG(D_TRACE, "srxd[%p] target_node [%u]\n", srxd, 
	       srxd->gm_source_node);

	GMNAL_GM_LOCK(nal_data);
	gm_status = gm_global_id_to_node_id(nal_data->gm_port, 
					    srxd->gm_source_node, &local_nid);
	GMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		CDEBUG(D_ERROR, "Failed to obtain local id\n");
		return;
	}
	CDEBUG(D_INFO, "Local Node_id is [%u][%x]\n", local_nid, local_nid);

	stxd = gmnal_get_stxd(nal_data, 1);
	CDEBUG(D_TRACE, "gmnal_large_tx_ack got stxd[%p]\n", stxd);

	stxd->nal_data = nal_data;
	stxd->type = GMNAL_LARGE_MESSAGE_ACK;

	/*
	 *	Copy gmnal_msg_hdr and portals header to the transmit buffer
	 *	Then copy the data in
	 */
	buffer = stxd->buffer;
	msghdr = (gmnal_msghdr_t*)buffer;

	/*
	 *	Add in the address of the original stxd from the sender node
	 *	so it knows which thread to notify.
	 */
	msghdr->magic = GMNAL_MAGIC;
	msghdr->type = GMNAL_LARGE_MESSAGE_ACK;
	msghdr->sender_node_id = nal_data->gm_global_nid;
	msghdr->stxd = srxd->source_stxd;
	CDEBUG(D_INFO, "processing msghdr at [%p]\n", buffer);

	CDEBUG(D_INFO, "sending\n");
	stxd->msg_size= sizeof(gmnal_msghdr_t);


	CDEBUG(D_NET, "Calling gm_send_to_peer port [%p] buffer [%p] 
	       gmsize [%lu] msize [%d] global_nid [%u] local_nid[%d] 
	       stxd [%p]\n", nal_data->gm_port, stxd->buffer, stxd->gm_size, 
	       stxd->msg_size, srxd->gm_source_node, local_nid, stxd);
	GMNAL_GM_LOCK(nal_data);
	stxd->gm_priority = GM_LOW_PRIORITY;
	stxd->gm_target_node = local_nid;
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, 
				      stxd->gm_size, stxd->msg_size, 
				      GM_LOW_PRIORITY, local_nid, 
				      gmnal_large_tx_ack_callback, 
				      (void*)stxd);
	
	GMNAL_GM_UNLOCK(nal_data);
	CDEBUG(D_INFO, "gmnal_large_tx_ack :: done\n");
		
	return;
}


/*
 *	A callback to indicate the small transmit operation is compete
 *	Check for errors and try to deal with them.
 *	Call lib_finalise to inform the client application that the 
 *	send is complete and the memory can be reused.
 *	Return the stxd when finished with it (returns a send token)
 */
void 
gmnal_large_tx_ack_callback(gm_port_t *gm_port, void *context, 
			     gm_status_t status)
{
	gmnal_stxd_t	*stxd = (gmnal_stxd_t*)context;
	gmnal_data_t	*nal_data = (gmnal_data_t*)stxd->nal_data;

	if (!stxd) {
		CDEBUG(D_ERROR, "send completion event for unknown stxd\n");
		return;
	}
	CDEBUG(D_TRACE, "send completion event for stxd [%p] status is [%d]\n",
	       stxd, status);
	gmnal_return_stxd(stxd->nal_data, stxd);

	GMNAL_GM_UNLOCK(nal_data);
	return;
}

/*
 *	Indicates the large transmit operation is compete.
 *	Called on transmit side (means data has been pulled  by receiver 
 *	or failed).
 *	Call lib_finalise to inform the client application that the send 
 *	is complete, deregister the memory and return the stxd. 
 *	Finally, report the rx buffer that the ack message was delivered in.
 */
void 
gmnal_large_tx_ack_received(gmnal_data_t *nal_data, gmnal_srxd_t *srxd)
{
	nal_cb_t	*nal_cb = nal_data->nal_cb;
	gmnal_stxd_t	*stxd = NULL;
	gmnal_msghdr_t	*msghdr = NULL;
	void		*buffer = NULL;
	struct	iovec	*iov;


	CDEBUG(D_TRACE, "gmnal_large_tx_ack_received buffer [%p]\n", buffer);

	buffer = srxd->buffer;
	msghdr = (gmnal_msghdr_t*)buffer;
	stxd = msghdr->stxd;

	CDEBUG(D_INFO, "gmnal_large_tx_ack_received stxd [%p]\n", stxd);

	if (lib_finalize(nal_cb, stxd, stxd->cookie) != PTL_OK) {
		CDEBUG(D_INFO, "Call to lib_finalize failed for stxd [%p]\n", 
		       stxd);
	}

	/*
	 *	extract the iovec from the stxd, deregister the memory.
	 *	free the space used to store the iovec
	 */
	iov = stxd->iov;
	while(stxd->niov--) {
		CDEBUG(D_INFO, "deregister memory [%p] size ["LPSZ"]\n",
		       iov->iov_base, iov->iov_len);
		GMNAL_GM_LOCK(nal_data);
		gm_deregister_memory(nal_data->gm_port, iov->iov_base, 
				     iov->iov_len);
		GMNAL_GM_UNLOCK(nal_data);
		iov++;
	}

	/*
	 *	return the send token
	 *	TO DO It is bad to hold onto the send token so long?
	 */
	gmnal_return_stxd(nal_data, stxd);


	/*
	 *	requeue the receive buffer 
	 */
	gmnal_rx_requeue_buffer(nal_data, srxd);
	

	return;
}




EXPORT_SYMBOL(gmnal_rx_thread);
EXPORT_SYMBOL(gmnal_ct_thread);
EXPORT_SYMBOL(gmnal_pre_receive);
EXPORT_SYMBOL(gmnal_rx_requeue_buffer);
EXPORT_SYMBOL(gmnal_rx_bad);
EXPORT_SYMBOL(gmnal_small_rx);
EXPORT_SYMBOL(gmnal_large_tx);
EXPORT_SYMBOL(gmnal_large_tx_callback);
EXPORT_SYMBOL(gmnal_small_tx_callback);
