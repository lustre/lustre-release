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
 *	This file contains all lgmnal send and receive functions
 */

#include "lgmnal.h"

/*
 *	The recevive thread
 *	This is main thread of execution for the receive side
 *	This guy waits in gm_blocking_recvive and gets
 *	woken up when the myrinet adaptor gets an interrupt.
 *	Hands off processing of small messages and blocks again
 */
int
lgmnal_rx_thread(void *arg)
{
	lgmnal_data_t		*nal_data;
	gm_recv_event_t		*rxevent = NULL;
	gm_recv_t		*recv = NULL;
	void			*buffer;

	if (!arg) {
		LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("RXTHREAD:: This is the lgmnal_rx_thread. NO nal_data. Exiting\n", arg));
		return(-1);
	}

	nal_data = (lgmnal_data_t*)arg;
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("RXTHREAD:: This is the lgmnal_rx_thread nal_data is [%p]\n", arg));

	nal_data->rxthread_flag = LGMNAL_THREAD_STARTED;
	while (nal_data->rxthread_flag == LGMNAL_THREAD_STARTED) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: lgmnal_rx_thread waiting for LGMNAL_CONTINUE flag\n"));
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(1024);
		
	}

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: calling daemonize\n"));
	daemonize();
	LGMNAL_GM_LOCK(nal_data);
	while(nal_data->rxthread_flag == LGMNAL_THREAD_CONTINUE) {
		LGMNAL_PRINT(LGMNAL_DEBUG_V, ("RXTHREAD:: Receive thread waiting\n"));
		rxevent = gm_blocking_receive_no_spin(nal_data->gm_port);
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: receive thread got [%s]\n", lgmnal_rxevent(rxevent)));
		if (nal_data->rxthread_flag != LGMNAL_THREAD_CONTINUE) {
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: Receive thread time to exit\n"));
			break;
		}
		switch (GM_RECV_EVENT_TYPE(rxevent)) {

			case(GM_RECV_EVENT):
				LGMNAL_PRINT(LGMNAL_DEBUG_V, ("RXTHREAD:: GM_RECV_EVENT\n"));
				recv = (gm_recv_t*)&(rxevent->recv);
				buffer = gm_ntohp(recv->buffer);
				switch(((lgmnal_msghdr_t*)buffer)->type) {
				case(LGMNAL_SMALL_MESSAGE):
					LGMNAL_GM_UNLOCK(nal_data);
					lgmnal_pre_receive(nal_data, recv, LGMNAL_SMALL_MESSAGE);
					LGMNAL_GM_LOCK(nal_data);
				break;	
				case(LGMNAL_LARGE_MESSAGE_INIT):
					LGMNAL_GM_UNLOCK(nal_data);
					lgmnal_pre_receive(nal_data, recv, LGMNAL_LARGE_MESSAGE_INIT);
					LGMNAL_GM_LOCK(nal_data);
				break;	
				case(LGMNAL_LARGE_MESSAGE_ACK):
					LGMNAL_GM_UNLOCK(nal_data);
					lgmnal_pre_receive(nal_data, recv, LGMNAL_LARGE_MESSAGE_ACK);
					LGMNAL_GM_LOCK(nal_data);
				break;	
				default:
					LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("RXTHREAD:: Unsupported message type\n"));
					/*
					 * Will get deadlock here as
					 * GM_LOCK is required by badrx_message
					 * to requeue the buffer
					 */
					LGMNAL_GM_UNLOCK(nal_data);
					lgmnal_rx_bad(nal_data, recv, NULL);
					LGMNAL_GM_LOCK(nal_data);
				}
			break;
			case(_GM_SLEEP_EVENT):
				/*
				 *	Blocking receive above just returns
				 *	immediatly with _GM_SLEEP_EVENT
				 *	Don't know what this is
				 */
				LGMNAL_PRINT(LGMNAL_DEBUG_V, ("RXTHREAD:: Sleeping in gm_unknown\n"));
				LGMNAL_GM_UNLOCK(nal_data);
				gm_unknown(nal_data->gm_port, rxevent);
				LGMNAL_GM_LOCK(nal_data);
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: Awake from gm_unknown\n"));
				break;
				
			default:
				/*
				 *	Don't know what this is
				 *	gm_unknown will make sense of it
				 */
				LGMNAL_PRINT(LGMNAL_DEBUG_V, ("RXTHREAD:: Passing event to gm_unknown\n"));
				LGMNAL_GM_UNLOCK(nal_data);
				gm_unknown(nal_data->gm_port, rxevent);
				LGMNAL_GM_LOCK(nal_data);
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: Processed unknown event\n"));
				
		}

		
	}
	LGMNAL_GM_UNLOCK(nal_data);
	nal_data->rxthread_flag = LGMNAL_THREAD_STOPPED;
	LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("RXTHREAD:: The lgmnal_receive_thread nal_data [%p] is exiting\n", nal_data));
	return(LGMNAL_STATUS_OK);
}





/*
 *	Start processing a small message receive
 *	Get here from lgmnal_receive_thread
 *	Hand off to lib_parse, which calls cb_recv
 *	which hands back to lgmnal_small_receive
 *	Deal with all endian stuff here (if we can!)
 */
int
lgmnal_pre_receive(lgmnal_data_t *nal_data, gm_recv_t *recv, int lgmnal_type)
{
	lgmnal_srxd_t	*srxd = NULL;
	void		*buffer = NULL;
	unsigned int snode, sport, type, length;
	lgmnal_msghdr_t	*lgmnal_msghdr;
	ptl_hdr_t	*portals_hdr;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_pre_receive nal_data [%p], recv [%p] type [%d]\n", nal_data, recv, lgmnal_type));

	buffer = gm_ntohp(recv->buffer);;
	snode = (int)gm_ntoh_u16(recv->sender_node_id);
	sport = (int)gm_ntoh_u8(recv->sender_port_id);
	type = (int)gm_ntoh_u8(recv->type);
	buffer = gm_ntohp(recv->buffer);
	length = (int) gm_ntohl(recv->length);

	lgmnal_msghdr = (lgmnal_msghdr_t*)buffer;
	portals_hdr = (ptl_hdr_t*)(buffer+LGMNAL_MSGHDR_SIZE);

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("rx_event:: Sender node [%d], Sender Port [%d], type [%d], length [%d], buffer [%p]\n",
				snode, sport, type, length, buffer));
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_msghdr:: Sender node [%u], magic [%lx], lgmnal_type [%d]\n",
				lgmnal_msghdr->sender_node_id, lgmnal_msghdr->magic, lgmnal_msghdr->type));
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("portals_hdr:: Sender node [%ul], dest_node [%ul]\n",
				portals_hdr->src_nid, portals_hdr->dest_nid));

	
	/*
 	 *	Get a receive descriptor for this message
	 */
	srxd = lgmnal_rxbuffer_to_srxd(nal_data, buffer);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Back from lgmnal_rxbuffer_to_srxd\n"));
	srxd->nal_data = nal_data;
	if (!srxd) {
		LGMNAL_PRINT(LGMNAL_DEBUG, ("Failed to get receive descriptor for this buffer\n"));
		lib_parse(nal_data->nal_cb, portals_hdr, srxd);
		return(LGMNAL_STATUS_FAIL);
	}

	/*
 	 *	no need to bother portals library with this
	 */
	if (lgmnal_type == LGMNAL_LARGE_MESSAGE_ACK) {
		lgmnal_large_tx_ack_received(nal_data, srxd);
		return(LGMNAL_STATUS_OK);
	}

	srxd->type = lgmnal_type;
	srxd->nsiov = lgmnal_msghdr->niov;
	srxd->gm_source_node = lgmnal_msghdr->sender_node_id;
	
	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("Calling lib_parse buffer is [%p]\n", buffer+LGMNAL_MSGHDR_SIZE));
	/*
 	 *	control passes to lib, which calls cb_recv 
	 *	cb_recv is responsible for returning the buffer 
	 *	for future receive
	 */
	lib_parse(nal_data->nal_cb, portals_hdr, srxd);

	return(LGMNAL_STATUS_OK);
}



/*
 *	After a receive has been processed, 
 *	hang out the receive buffer again.
 *	This implicitly returns a receive token.
 */
int
lgmnal_rx_requeue_buffer(lgmnal_data_t *nal_data, lgmnal_srxd_t *srxd)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_rx_requeue_buffer\n"));

	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("requeueing srxd[%p] nal_data[%p]\n", srxd, nal_data));

	LGMNAL_GM_LOCK(nal_data);
	gm_provide_receive_buffer_with_tag(nal_data->gm_port, srxd->buffer,
					srxd->gmsize, GM_LOW_PRIORITY, 0 );
	LGMNAL_GM_UNLOCK(nal_data);

	return(LGMNAL_STATUS_OK);
}


/*
 *	Handle a bad message
 *	A bad message is one we don't expect or can't interpret
 */
int
lgmnal_rx_bad(lgmnal_data_t *nal_data, gm_recv_t *recv, lgmnal_srxd_t *srxd)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("Can't handle message\n"));

	if (!srxd)
		srxd = lgmnal_rxbuffer_to_srxd(nal_data, gm_ntohp(recv->buffer));
	if (srxd) {
		lgmnal_rx_requeue_buffer(nal_data, srxd);
	} else {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("Can't find a descriptor for this buffer\n"));
		/*
		 *	get rid of it ?
		 */
		return(LGMNAL_STATUS_FAIL);
	}

	return(LGMNAL_STATUS_OK);
}



/*
 *	Process a small message receive.
 *	Get here from lgmnal_receive_thread, lgmnal_pre_receive
 *	lib_parse, cb_recv
 *	Put data from prewired receive buffer into users buffer(s)
 *	Hang out the receive buffer again for another receive
 *	Call lib_finalize
 */
int
lgmnal_small_rx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, unsigned int niov, 
							struct iovec *iov, size_t mlen, size_t rlen)
{
	lgmnal_srxd_t	*srxd = NULL;
	void	*buffer = NULL;
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_small_rx niov [%d] mlen[%d]\n", niov, mlen));

	if (!private) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_small_rx no context\n"));
		lib_finalize(nal_cb, private, cookie);
		return(PTL_FAIL);
	}

	srxd = (lgmnal_srxd_t*)private;
	buffer = srxd->buffer;
	buffer += sizeof(lgmnal_msghdr_t);
	buffer += sizeof(ptl_hdr_t);

	while(niov--) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing [%p] len [%d]\n", iov, iov->iov_len));
		gm_bcopy(buffer, iov->iov_base, iov->iov_len);			
		buffer += iov->iov_len;
		iov++;
	}


	/*
 	 *	let portals library know receive is complete
	 */
	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("calling lib_finalize\n"));
	if (lib_finalize(nal_cb, private, cookie) != PTL_OK) {
		/* TO DO what to do with failed lib_finalise? */
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lib_finalize failed\n"));
	}
	/*
	 *	return buffer so it can be used again
	 */
	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("calling gm_provide_receive_buffer\n"));
	LGMNAL_GM_LOCK(nal_data);
	gm_provide_receive_buffer_with_tag(nal_data->gm_port, srxd->buffer, srxd->gmsize, GM_LOW_PRIORITY, 0);	
	LGMNAL_GM_UNLOCK(nal_data);

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
lgmnal_small_tx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr, int type,
	ptl_nid_t global_nid, ptl_pid_t pid, unsigned int niov, struct iovec *iov, int size)
{
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;
	lgmnal_stxd_t	*stxd = NULL;
	void		*buffer = NULL;
	lgmnal_msghdr_t	*msghdr = NULL;
	int		tot_size = 0;
	unsigned int	local_nid;
	gm_status_t	gm_status = GM_SUCCESS;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_small_tx nal_cb [%p] private [%p] cookie [%p] hdr [%p] type [%d] global_nid [%lu] pid [%d] niov [%d] iov [%p] size [%d]\n", nal_cb, private, cookie, hdr, type, global_nid, pid, niov, iov, size));

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("portals_hdr:: dest_nid [%lu], src_nid [%lu]\n", hdr->dest_nid, hdr->src_nid));

	if (!nal_data) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("no nal_data\n"));
		return(LGMNAL_STATUS_FAIL);
	} else {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("nal_data [%p]\n", nal_data));
	}

	LGMNAL_GM_LOCK(nal_data);
	gm_status = gm_global_id_to_node_id(nal_data->gm_port, global_nid, &local_nid);
	LGMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("Failed to obtain local id\n"));
		return(LGMNAL_STATUS_FAIL);
	}
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Local Node_id is [%u][%x]\n", local_nid, local_nid));

	stxd = lgmnal_get_stxd(nal_data, 1);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("stxd [%p]\n", stxd));

	stxd->type = LGMNAL_SMALL_MESSAGE;
	stxd->cookie = cookie;

	/*
	 *	Copy lgmnal_msg_hdr and portals header to the transmit buffer
	 *	Then copy the data in
	 */
	buffer = stxd->buffer;
	msghdr = (lgmnal_msghdr_t*)buffer;

	msghdr->magic = LGMNAL_MAGIC;
	msghdr->type = LGMNAL_SMALL_MESSAGE;
	msghdr->sender_node_id = nal_data->gm_global_nid;
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing msghdr at [%p]\n", buffer));

	buffer += sizeof(lgmnal_msghdr_t);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Advancing buffer pointer by [%x] to [%p]\n", sizeof(lgmnal_msghdr_t), buffer));

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing  portals hdr at [%p]\n", buffer));
	gm_bcopy(hdr, buffer, sizeof(ptl_hdr_t));

	buffer += sizeof(ptl_hdr_t);

	while(niov--) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing iov [%p] len [%d] to [%p]\n", iov, iov->iov_len, buffer));
		gm_bcopy(iov->iov_base, buffer, iov->iov_len);
		buffer+= iov->iov_len;
		iov++;
	}

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("sending\n"));
	tot_size = size+sizeof(ptl_hdr_t)+sizeof(lgmnal_msghdr_t);
	stxd->msg_size = tot_size;


	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("Calling gm_send_to_peer port [%p] buffer [%p] gmsize [%d] msize [%d] global_nid [%lu][%x] local_nid[%d] stxd [%p]\n",
			nal_data->gm_port, stxd->buffer, stxd->gm_size, stxd->msg_size, global_nid, local_nid, stxd));
	LGMNAL_GM_LOCK(nal_data);
	stxd->gm_priority = GM_LOW_PRIORITY;
	stxd->gm_target_node = local_nid;
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, stxd->gm_size, stxd->msg_size, GM_LOW_PRIORITY, local_nid, lgmnal_small_tx_callback, (void*)stxd);
	
	LGMNAL_GM_UNLOCK(nal_data);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("done\n"));
		
	return(PTL_OK);
}


/*
 *	A callback to indicate the small transmit operation is compete
 *	Check for erros and try to deal with them.
 *	Call lib_finalise to inform the client application that the send is complete
 *	and the memory can be reused.
 *	Return the stxd when finished with it (returns a send token)
 */
void 
lgmnal_small_tx_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{
	lgmnal_stxd_t	*stxd = (lgmnal_stxd_t*)context;
	lib_msg_t	*cookie = stxd->cookie;
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)stxd->nal_data;
	nal_cb_t	*nal_cb = nal_data->nal_cb;

	if (!stxd) {
		LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("send completion event for unknown stxd\n"));
		return;
	}
	if (status != GM_SUCCESS) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("Result of send stxd [%p] is [%s]\n", stxd, lgmnal_gm_error(status)));
	}

	switch(status) {
  		case(GM_SUCCESS):
		break;



  		case(GM_SEND_DROPPED):
		/*
		 *	do a resend on the dropped ones
		 */
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("send stxd [%p] was dropped resending\n", context));
		gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, stxd->gm_size, stxd->msg_size, stxd->gm_priority, stxd->gm_target_node, lgmnal_small_tx_callback, context);
		
		return;
  		case(GM_TIMED_OUT):
		/*
		 *	drop these ones
		 */
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_small_tx_callback calling gm_drop_sends\n"));
			gm_drop_sends(nal_data->gm_port, stxd->gm_priority, stxd->gm_target_node, LGMNAL_GM_PORT, lgmnal_drop_sends_callback, context);

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
  		case(GM_SEND_TIMED_OUT):
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
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("Unknown send error\n"));
	}
	if (stxd->type == LGMNAL_LARGE_MESSAGE_INIT) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_small_tx_callback large transmit done\n"));
		return;
	}
	if (lib_finalize(nal_cb, stxd, cookie) != PTL_OK) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Call to lib_finalize failed for stxd [%p]\n", stxd));
	}
	lgmnal_return_stxd(nal_data, stxd);
	return;
}



void lgmnal_drop_sends_callback(struct gm_port *gm_port, void *context, gm_status_t status)
{
	lgmnal_stxd_t	*stxd = (lgmnal_stxd_t*)context;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_drop_sends_callback :: status is [%d] context is [%p]\n", status, context));
	if (status == GM_SUCCESS) {
		gm_send_to_peer_with_callback(gm_port, stxd->buffer, stxd->gm_size, stxd->msg_size, stxd->gm_priority, stxd->gm_target_node, lgmnal_small_tx_callback, context);
	} else {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_drop send_to_peer status for stxd [%p} is [%d][%s]\n", 
						stxd, status, lgmnal_gm_error(status)));
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
lgmnal_large_tx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr, int type,
	ptl_nid_t global_nid, ptl_pid_t pid, unsigned int niov, struct iovec *iov, int size)
{

	lgmnal_data_t	*nal_data;
	lgmnal_stxd_t	*stxd = NULL;
	void		*buffer = NULL;
	lgmnal_msghdr_t	*msghdr = NULL;
	unsigned int	local_nid;
	int		mlen = 0;	/* the size of the init message data */
	struct iovec	*iov_dup = NULL;
	gm_status_t	gm_status;
	int		niov_dup;


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_large_tx nal_cb [%p] private [%p], cookie [%p] hdr [%p], type [%d] global_nid [%u], pid [%d], niov [%d], iov [%p], size [%d]\n", nal_cb, private, cookie, hdr, type, global_nid, pid, niov, iov, size));

	if (nal_cb)
		nal_data = (lgmnal_data_t*)nal_cb->nal_data;
	else  {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("no nal_cb.\n"));
		return(LGMNAL_STATUS_FAIL);
	}
	

	/*
	 *	Get stxd and buffer. Put local address of data in buffer, 
	 *	send local addresses to target, 
	 *	wait for the target node to suck the data over.
	 *	The stxd is used to ren
	 */
	stxd = lgmnal_get_stxd(nal_data, 1);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("stxd [%p]\n", stxd));

	stxd->type = LGMNAL_LARGE_MESSAGE_INIT;
	stxd->cookie = cookie;

	/*
	 *	Copy lgmnal_msg_hdr and portals header to the transmit buffer
	 *	Then copy the iov in
	 */
	buffer = stxd->buffer;
	msghdr = (lgmnal_msghdr_t*)buffer;

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing msghdr at [%p]\n", buffer));

	msghdr->magic = LGMNAL_MAGIC;
	msghdr->type = LGMNAL_LARGE_MESSAGE_INIT;
	msghdr->sender_node_id = nal_data->gm_global_nid;
	msghdr->stxd = stxd;
	msghdr->niov = niov ;
	buffer += sizeof(lgmnal_msghdr_t);
	mlen = sizeof(lgmnal_msghdr_t);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("mlen is [%d]\n", mlen));


	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing  portals hdr at [%p]\n", buffer));

	gm_bcopy(hdr, buffer, sizeof(ptl_hdr_t));
	buffer += sizeof(ptl_hdr_t);
	mlen += sizeof(ptl_hdr_t); 
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("mlen is [%d]\n", mlen));

	/*
	 *	copy the iov to the buffer so target knows where to get the data from
	 */
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing iov to [%p]\n", buffer));
	gm_bcopy(iov, buffer, niov*sizeof(struct iovec));
	mlen += niov*(sizeof(struct iovec));
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("mlen is [%d]\n", mlen));


	/*
	 *	Store the iovs in the stxd for we can get them later if we need them
	 */
	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("Copying iov [%p] to [%p]\n", iov, stxd->iov));
	gm_bcopy(iov, stxd->iov, niov*sizeof(struct iovec));
	stxd->niov = niov;
	

	/*
	 *	register the memory so the NIC can get hold of the data
	 *	This is a slow process. it'd be good to overlap it with something else.
	 */
	iov_dup = iov;
	niov_dup = niov;
	while(niov--) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Registering memory [%p] len [%d] \n", iov->iov_base, iov->iov_len));
		LGMNAL_GM_LOCK(nal_data);
		gm_status = gm_register_memory(nal_data->gm_port, iov->iov_base, iov->iov_len);
		if (gm_status != GM_SUCCESS) {
			LGMNAL_GM_UNLOCK(nal_data);
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("gm_register_memory returns [%d][%s] for memory [%p] len [%d]\n", 
						gm_status, lgmnal_gm_error(gm_status), iov->iov_base, iov->iov_len));
			LGMNAL_GM_LOCK(nal_data);
			while (iov_dup != iov) {
				gm_deregister_memory(nal_data->gm_port, iov_dup->iov_base, iov_dup->iov_len);
				iov_dup++;
			}
			LGMNAL_GM_UNLOCK(nal_data);
			lgmnal_return_stxd(nal_data, stxd);
			return(PTL_FAIL);
		}

		LGMNAL_GM_UNLOCK(nal_data);
		iov++;
	}

	/*
 	 *	Send the init message to the target
	 */
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("sending mlen [%d]\n", mlen));
	LGMNAL_GM_LOCK(nal_data);
	gm_status = gm_global_id_to_node_id(nal_data->gm_port, global_nid, &local_nid);
	if (gm_status != GM_SUCCESS) {
		LGMNAL_GM_UNLOCK(nal_data);
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("Failed to obtain local id\n"));
		lgmnal_return_stxd(nal_data, stxd);
		/* TO DO deregister memory on failure */
		return(LGMNAL_STATUS_FAIL);
	}
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Local Node_id is [%d]\n", local_nid));
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, stxd->gm_size, mlen, GM_LOW_PRIORITY, local_nid, lgmnal_large_tx_callback, (void*)stxd);
	LGMNAL_GM_UNLOCK(nal_data);
	
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("done\n"));
		
	return(PTL_OK);
}

/*
 *	Callback function indicates that send of buffer with large message iovec 
 *	has completed (or failed).
 */
void 
lgmnal_large_tx_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{
	lgmnal_small_tx_callback(gm_port, context, status);

}



/*
 *	Have received a buffer that contains an iovec of the sender. 
 *	Do a gm_register_memory of the receivers buffer and then do a get
 *	data from the sender.
 */
int
lgmnal_large_rx(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, unsigned int nriov, 
					struct iovec *riov, size_t mlen, size_t rlen)
{
	lgmnal_data_t	*nal_data = nal_cb->nal_data;
	lgmnal_srxd_t	*srxd = (lgmnal_srxd_t*)private;
	void		*buffer = NULL;
	struct	iovec	*riov_dup;
	int		nriov_dup;
	lgmnal_msghdr_t	*msghdr = NULL;
	gm_status_t	gm_status;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_large_rx :: nal_cb[%p], private[%p], cookie[%p], niov[%d], iov[%p], mlen[%d], rlen[%d]\n",
						nal_cb, private, cookie, nriov, riov, mlen, rlen));

	if (!srxd) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_large_rx no context\n"));
		lib_finalize(nal_cb, private, cookie);
		return(PTL_FAIL);
	}

	buffer = srxd->buffer;
	msghdr = (lgmnal_msghdr_t*)buffer;
	buffer += sizeof(lgmnal_msghdr_t);
	buffer += sizeof(ptl_hdr_t);

	/*
	 *	Store the senders stxd address in the srxd for this message
	 *	The lgmnal_large_message_ack needs it to notify the sender
	 *	the pull of data is complete
	 */
	srxd->source_stxd = msghdr->stxd;

	/*
	 *	Register the receivers memory
	 *	get the data,
	 *	tell the sender that we got the data
	 *	then tell the receiver we got the data
	 */
	nriov_dup = nriov;
	riov_dup = riov;
	while(nriov--) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Registering memory [%p] len [%d] \n", riov->iov_base, riov->iov_len));
		LGMNAL_GM_LOCK(nal_data);
		gm_status = gm_register_memory(nal_data->gm_port, riov->iov_base, riov->iov_len);
		if (gm_status != GM_SUCCESS) {
			LGMNAL_GM_UNLOCK(nal_data);
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("gm_register_memory returns [%d][%s] for memory [%p] len [%d]\n", 
						gm_status, lgmnal_gm_error(gm_status), riov->iov_base, riov->iov_len));
			LGMNAL_GM_LOCK(nal_data);
			while (riov_dup != riov) {
				gm_deregister_memory(nal_data->gm_port, riov_dup->iov_base, riov_dup->iov_len);
				riov_dup++;
			}
			LGMNAL_GM_LOCK(nal_data);
			/*
			 *	give back srxd and buffer. Send NACK to sender
			 */
			return(PTL_FAIL);
		}
		LGMNAL_GM_UNLOCK(nal_data);
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
	if (lgmnal_remote_get(srxd, srxd->nsiov, (struct iovec*)buffer, nriov_dup, riov_dup) != LGMNAL_STATUS_OK) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("can't get the data"));
	}

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmanl_large_rx done\n"));

	return(PTL_OK);
}


/*
 *	Perform a number of remote gets as part of receiving a large message.
 *	The final one to complete (i.e. the last callback to get called)
 *	tidies up.
 *	gm_get requires a send token.
 */
int
lgmnal_remote_get(lgmnal_srxd_t *srxd, int nsiov, struct iovec *siov, int nriov, struct iovec *riov)
{

	int	ncalls = 0;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_remote_get srxd[%p], nriov[%d], riov[%p], nsiov[%d], siov[%p]\n",
				srxd, nriov, riov, nsiov, siov));


	ncalls = lgmnal_copyiov(0, srxd, nsiov, siov, nriov, riov);
	if (ncalls < 0) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_remote_get there's something wrong with the iovecs\n"));
		return(LGMNAL_STATUS_FAIL);
	}
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_remote_get ncalls [%d]\n", ncalls));
	spin_lock_init(&srxd->callback_lock);
	srxd->ncallbacks = ncalls;
	srxd->callback_status = 0;

	ncalls = lgmnal_copyiov(1, srxd, nsiov, siov, nriov, riov);
	if (ncalls < 0) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_remote_get there's something wrong with the iovecs\n"));
		return(LGMNAL_STATUS_FAIL);
	}

	return(LGMNAL_STATUS_OK);

}


/*
 *	pull data from source node (source iovec) to a local iovec.
 *	The iovecs may not match which adds the complications below.
 *	Count the number of gm_gets that will be required to the callbacks
 *	can determine who is the last one.
 */	
int
lgmnal_copyiov(int do_copy, lgmnal_srxd_t *srxd, int nsiov, struct iovec *siov, int nriov, struct iovec *riov)
{

	int	ncalls = 0;
	int	slen = siov->iov_len, rlen = riov->iov_len;
	char	*sbuf = siov->iov_base, *rbuf = riov->iov_base;	
	unsigned int	source_node;
	lgmnal_stxd_t	*stxd = NULL;
	lgmnal_data_t	*nal_data = srxd->nal_data;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_copyiov copy[%d] nal_data[%p]\n", do_copy, nal_data));
	if (do_copy) {
		if (!nal_data) {
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_copyiov Bad args No nal_data\n"));
			return(LGMNAL_STATUS_FAIL);
		}
		LGMNAL_GM_LOCK(nal_data);
		if (gm_global_id_to_node_id(nal_data->gm_port, srxd->gm_source_node, &source_node) != GM_SUCCESS) {
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_copyiov :: cannot resolve global_id [%u] to local node_id\n", 
							srxd->gm_source_node));
			LGMNAL_GM_UNLOCK(nal_data);
			return(LGMNAL_STATUS_FAIL);
		}
		LGMNAL_GM_UNLOCK(nal_data);
		/*
		 *	We need a send token to use gm_get
		 *	getting an stxd gets us a send token.
		 *	the stxd is used as the context to the
	 	 *	callback function (so stxd can be returned).
		 *	Set pointer in stxd to srxd so callback count in srxd
		 *	can be decremented to find last callback to complete
		 */
		stxd = lgmnal_get_stxd(nal_data, 1);
		stxd->srxd = srxd;
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_copyiov source node is G[%u]L[%d]\n", srxd->gm_source_node, source_node));
	}

	do {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("sbuf[%p] slen[%d] rbuf[%p], rlen[%d]\n",
				sbuf, slen, rbuf, rlen));
		if (slen > rlen) {
			ncalls++;
			if (do_copy) {
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("slen>rlen\n"));
				LGMNAL_GM_LOCK(nal_data);
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Calling gm_get with port[%p] sbuf[%p], rbuf[%p], len[%d], priority[%d], source_node[%d], stxd[%p]\n", nal_data->gm_port, (gm_remote_ptr_t)sbuf, rbuf, rlen, GM_LOW_PRIORITY, source_node, stxd));
				gm_get(nal_data->gm_port, (gm_remote_ptr_t)sbuf, rbuf, rlen, GM_LOW_PRIORITY,
						source_node, LGMNAL_GM_PORT, lgmnal_remote_get_callback, stxd);
				LGMNAL_GM_UNLOCK(nal_data);
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
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("slen<rlen\n"));
				LGMNAL_GM_LOCK(nal_data);
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Calling gm_get with port[%p] sbuf[%p], rbuf[%p], len[%d], priority[%d], source_node[%d], stxd[%p]\n", nal_data->gm_port, (gm_remote_ptr_t)sbuf, rbuf, rlen, GM_LOW_PRIORITY, source_node, stxd));
				gm_get(srxd->nal_data->gm_port, (gm_remote_ptr_t)sbuf, rbuf, slen, GM_LOW_PRIORITY,
						source_node, LGMNAL_GM_PORT, lgmnal_remote_get_callback, stxd);
				LGMNAL_GM_UNLOCK(nal_data);
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
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("rlen=slen\n"));
				LGMNAL_GM_LOCK(nal_data);
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Calling gm_get with port[%p] sbuf[%p], rbuf[%p], len[%d], priority[%d], source_node[%d], stxd[%p]\n", 
				nal_data->gm_port, (gm_remote_ptr_t)sbuf, rbuf, rlen, GM_LOW_PRIORITY, source_node, stxd));
				gm_get(srxd->nal_data->gm_port, (gm_remote_ptr_t)sbuf, rbuf, rlen, GM_LOW_PRIORITY,
						source_node, LGMNAL_GM_PORT, lgmnal_remote_get_callback, stxd);
				LGMNAL_GM_UNLOCK(nal_data);
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
lgmnal_remote_get_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{

	lgmnal_stxd_t	*stxd = (lgmnal_stxd_t*)context;
	lgmnal_srxd_t	*srxd = stxd->srxd;
	nal_cb_t	*nal_cb = srxd->nal_data->nal_cb;
	int		lastone;
	struct	iovec	*riov;
	int		nriov;
	lgmnal_data_t	*nal_data;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_remote_get_callback called for context [%p]\n", context));

	if (status != GM_SUCCESS) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_remote_get_callback reports error [%d][%s]\n", status, lgmnal_gm_error(status)));
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
	lgmnal_return_stxd(nal_data, stxd);

	if (!lastone) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_remote_get_callback NOT final callback context[%p]\n", srxd));
		return;
	}
	
	/*
	 *	Let our client application proceed
	 */	
	LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_remote_get_callback final callback context[%p]\n", srxd));
	if (lib_finalize(nal_cb, srxd, srxd->cookie) != PTL_OK) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmanl_remote_get_callback Call to lib_finalize failed for srxd [%p]\n", srxd));
	}

	/*
	 *	send an ack to the sender to let him know we got the data
	 */
	lgmnal_large_tx_ack(nal_data, srxd);

	/*
	 *	Unregister the memory that was used
	 */
	nriov = srxd->nriov;
	riov = srxd->riov;
	LGMNAL_GM_LOCK(nal_data);
	while (nriov--) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_remote_get_callback deregister memory [%p]\n", riov->iov_base));
		if (gm_deregister_memory(srxd->nal_data->gm_port, riov->iov_base, riov->iov_len)) {
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_remote_get_callback failed to deregister memory [%p]\n", riov->iov_base));
		}
		riov++;
	}
	LGMNAL_GM_UNLOCK(nal_data);
	PORTAL_FREE(srxd->riov, sizeof(struct iovec)*nriov);

	/*
	 *	repost the receive buffer (return receive token)
	 */
	LGMNAL_GM_LOCK(nal_data);
	gm_provide_receive_buffer_with_tag(nal_data->gm_port, srxd->buffer, srxd->gmsize, GM_LOW_PRIORITY, 0);	
	LGMNAL_GM_UNLOCK(nal_data);
	
	return;
}


/*
 *	Called on target node.
 *	After pulling data from a source node
 *	send an ack message to indicate the large transmit is complete.
 */
void 
lgmnal_large_tx_ack(lgmnal_data_t *nal_data, lgmnal_srxd_t *srxd)
{

	lgmnal_stxd_t	*stxd;
	lgmnal_msghdr_t *msghdr;
	void		*buffer = NULL;
	unsigned int	local_nid;
	gm_status_t	gm_status = GM_SUCCESS;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_large_tx_ack srxd[%p] target_node [%u]\n", srxd, srxd->gm_source_node));

	LGMNAL_GM_LOCK(nal_data);
	gm_status = gm_global_id_to_node_id(nal_data->gm_port, srxd->gm_source_node, &local_nid);
	LGMNAL_GM_UNLOCK(nal_data);
	if (gm_status != GM_SUCCESS) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("Failed to obtain local id\n"));
		return;
	}
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Local Node_id is [%u][%x]\n", local_nid, local_nid));

	stxd = lgmnal_get_stxd(nal_data, 1);
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_large_tx_ack got stxd[%p]\n", stxd));

	stxd->nal_data = nal_data;
	stxd->type = LGMNAL_LARGE_MESSAGE_ACK;

	/*
	 *	Copy lgmnal_msg_hdr and portals header to the transmit buffer
	 *	Then copy the data in
	 */
	buffer = stxd->buffer;
	msghdr = (lgmnal_msghdr_t*)buffer;

	/*
	 *	Add in the address of the original stxd from the sender node
	 *	so it knows which thread to notify.
	 */
	msghdr->magic = LGMNAL_MAGIC;
	msghdr->type = LGMNAL_LARGE_MESSAGE_ACK;
	msghdr->sender_node_id = nal_data->gm_global_nid;
	msghdr->stxd = srxd->source_stxd;
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing msghdr at [%p]\n", buffer));

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("sending\n"));
	stxd->msg_size= sizeof(lgmnal_msghdr_t);


	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("Calling gm_send_to_peer port [%p] buffer [%p] gmsize [%d] msize [%d] global_nid [%u] local_nid[%d] stxd [%p]\n",
			nal_data->gm_port, stxd->buffer, stxd->gm_size, stxd->msg_size, srxd->gm_source_node, local_nid, stxd));
	LGMNAL_GM_LOCK(nal_data);
	stxd->gm_priority = GM_LOW_PRIORITY;
	stxd->gm_target_node = local_nid;
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, stxd->gm_size, stxd->msg_size, GM_LOW_PRIORITY, local_nid, lgmnal_large_tx_ack_callback, (void*)stxd);
	
	LGMNAL_GM_UNLOCK(nal_data);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_large_tx_ack :: done\n"));
		
	return;
}


/*
 *	A callback to indicate the small transmit operation is compete
 *	Check for errors and try to deal with them.
 *	Call lib_finalise to inform the client application that the send is complete
 *	and the memory can be reused.
 *	Return the stxd when finished with it (returns a send token)
 */
void 
lgmnal_large_tx_ack_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{
	lgmnal_stxd_t	*stxd = (lgmnal_stxd_t*)context;
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)stxd->nal_data;

	if (!stxd) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_large_tx_ack_callback send completion event for unknown stxd\n"));
		return;
	}
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_large_tx_ack_callback send completion event for stxd [%p] status is [%d]\n", stxd, status));
	lgmnal_return_stxd(stxd->nal_data, stxd);

	LGMNAL_GM_UNLOCK(nal_data);
	return;
}

/*
 *	Indicates the large transmit operation is compete.
 *	Called on transmit side (means data has been pulled  by receiver or failed).
 *	Call lib_finalise to inform the client application that the send is complete,
 *	deregister the memory and return the stxd. Finally, report the rx buffer that
 *	the ack message was delivered in.
 */
void 
lgmnal_large_tx_ack_received(lgmnal_data_t *nal_data, lgmnal_srxd_t *srxd)
{
	nal_cb_t	*nal_cb = nal_data->nal_cb;
	lgmnal_stxd_t	*stxd = NULL;
	lgmnal_msghdr_t	*msghdr = NULL;
	void		*buffer = NULL;
	struct	iovec	*iov;


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_large_tx_ack_received buffer [%p]\n", buffer));

	buffer = srxd->buffer;
	msghdr = (lgmnal_msghdr_t*)buffer;
	stxd = msghdr->stxd;

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_large_tx_ack_received stxd [%p]\n", stxd));

	if (lib_finalize(nal_cb, stxd, stxd->cookie) != PTL_OK) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Call to lib_finalize failed for stxd [%p]\n", stxd));
	}

	/*
	 *	extract the iovec from the stxd, deregister the memory.
	 *	free the space used to store the iovec
	 */
	iov = stxd->iov;
	while(stxd->niov--) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_large_tx_ack deregister memory [%p] size [%d]\n",
				iov->iov_base, iov->iov_len));
		LGMNAL_GM_LOCK(nal_data);
		gm_deregister_memory(nal_data->gm_port, iov->iov_base, iov->iov_len);
		LGMNAL_GM_UNLOCK(nal_data);
		iov++;
	}

	/*
	 *	return the send token
	 *	TO DO It is bad to hold onto the send token so long?
	 */
	lgmnal_return_stxd(nal_data, stxd);


	/*
	 *	requeue the receive buffer 
	 */
	lgmnal_rx_requeue_buffer(nal_data, srxd);
	

	return;
}

EXPORT_SYMBOL(lgmnal_rx_thread);
EXPORT_SYMBOL(lgmnal_pre_receive);
EXPORT_SYMBOL(lgmnal_rx_requeue_buffer);
EXPORT_SYMBOL(lgmnal_rx_bad);
EXPORT_SYMBOL(lgmnal_small_rx);
EXPORT_SYMBOL(lgmnal_large_tx);
EXPORT_SYMBOL(lgmnal_large_tx_callback);
EXPORT_SYMBOL(lgmnal_small_tx_callback);
