/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
  * vim:expandtab:shiftwidth=8:tabstop=8:
  *
  *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
  *
  *   This file is part of Lustre, http://www.lustre.org/
  *
  *   This file is free software; you can redistribute it and/or
  *   modify it under the terms of version 2.1 of the GNU Lesser General
  *   Public License as published by the Free Software Foundation.
  *
  *   Lustre is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *   GNU Lesser General Public License for more details.
  *
  *   You should have received a copy of the GNU Lesser General Public
  *   License along with Portals; if not, write to the Free Software
  *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
  */


/*
 *	This file contains all lgmnal send and receive functions
 */

#include "lgmnal.h"

int
lgmnal_requeue_rxbuffer(lgmnal_data_t *nal_data, lgmnal_srxd_t *srxd)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_requeue_rxbuffer\n"));

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
lgmnal_badrx_message(lgmnal_data_t *nal_data, gm_recv_t *recv, lgmnal_srxd_t *srxd)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("Can't handle message\n"));

	if (!srxd)
		srxd = lgmnal_rxbuffer_to_srxd(nal_data, gm_ntohp(recv->buffer));
	if (srxd) {
		lgmnal_requeue_rxbuffer(nal_data, srxd);
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
 *	Start processing a small message receive
 *	Get here from lgmnal_receive_thread
 *	Hand off to lib_parse, which calls cb_recv
 *	which hands back to lgmnal_small_receive2
 *	Deal with all endian stuff here (if we can!)
 */
int
lgmnal_small_receive1(lgmnal_data_t *nal_data, gm_recv_t *recv)
{
	lgmnal_srxd_t	*srxd = NULL;
	void		*buffer = NULL;
	unsigned int snode, sport, type, length;
	lgmnal_msghdr_t	*lgmnal_msghdr;
	ptl_hdr_t	*portals_hdr;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_small_receive1 nal_data [%p], recv [%p]\n", nal_data, recv));

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
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_msghdr:: Sender node [%u], magic [%lx], type [%d]\n",
				lgmnal_msghdr->sender_node_id, lgmnal_msghdr->magic, lgmnal_msghdr->type));
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("portals_hdr:: Sender node [%ul], dest_node [%ul]\n",
				portals_hdr->src_nid, portals_hdr->dest_nid));


	/*
 	 *	Get a transmit descriptor for this message
	 */
	srxd = lgmnal_rxbuffer_to_srxd(nal_data, buffer);
	LGMNAL_PRINT(LGMNAL_DEBUG, ("Back from lgmnal_rxbuffer_to_srxd\n"));
	if (!srxd) {
		LGMNAL_PRINT(LGMNAL_DEBUG, ("Failed to get receive descriptor for this buffer\n"));
		lib_parse(nal_data->nal_cb, portals_hdr, srxd);
		return(LGMNAL_STATUS_FAIL);
	}
	srxd->type = LGMNAL_SMALL_MESSAGE;
	
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
 *	Get here from lgmnal_receive_thread, lgmnal_small_receive1
 *	lib_parse, cb_recv
 *	Put data from prewired receive buffer into users buffer(s)
 *	Hang out the receive buffer again for another receive
 *	Call lib_finalize
 */
int
lgmnal_small_receive2(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, unsigned int niov, 
							struct iovec *iov, size_t mlen, size_t rlen)
{
	lgmnal_srxd_t	*srxd = NULL;
	void	*buffer = NULL;
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_small_receive2 niov [%d] mlen[%d]\n", niov, mlen));

	if (!private) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_small_receive2 no context\n"));
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
 *	The recevive thread
 *	This guy wait in gm_blocking_recvive and gets
 *	woken up when the myrinet adaptor gets an interrupt.
 *	Hands off processing of small messages and blocks again
 */
int
lgmnal_receive_thread(void *arg)
{
	lgmnal_data_t		*nal_data;
	gm_recv_event_t		*rxevent = NULL;
	gm_recv_t		*recv = NULL;
	void			*buffer;

	if (!arg) {
		LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("RXTHREAD:: This is the lgmnal_receive_thread. NO nal_data. Exiting\n", arg));
		return(-1);
	}

	nal_data = (lgmnal_data_t*)arg;
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("RXTHREAD:: This is the lgmnal_receive_thread nal_data is [%p]\n", arg));

	nal_data->rxthread_flag = LGMNAL_THREAD_STARTED;
	while (nal_data->rxthread_flag == LGMNAL_THREAD_STARTED) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: lgmnal_receive_threads waiting for LGMNAL_CONTINUE flag\n"));
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
				if (((lgmnal_msghdr_t*)buffer)->type == LGMNAL_SMALL_MESSAGE) {
					LGMNAL_GM_UNLOCK(nal_data);
					lgmnal_small_receive1(nal_data, recv);
					LGMNAL_GM_LOCK(nal_data);
				} else {
					LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("RXTHREAD:: Unsupported message type\n"));
					lgmnal_badrx_message(nal_data, recv, NULL);
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
				gm_unknown(nal_data->gm_port, rxevent);
				LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("RXTHREAD:: Processed unknown event\n"));
				
		}

		
	}
	LGMNAL_GM_UNLOCK(nal_data);
	nal_data->rxthread_flag = LGMNAL_THREAD_STOPPED;
	LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("RXTHREAD:: The lgmnal_receive_thread nal_data [%p] is exiting\n", nal_data));
	return(LGMNAL_STATUS_OK);
}


int
lgmnal_small_transmit(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr, int type,
	ptl_nid_t global_nid, ptl_pid_t pid, unsigned int niov, struct iovec *iov, int size)
{
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;
	lgmnal_stxd_t	*stxd = NULL;
	void		*buffer = NULL;
	lgmnal_msghdr_t	*msghdr = NULL;
	int		tot_size = 0;
	unsigned int	local_nid;
	gm_status_t	gm_status = GM_SUCCESS;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_small_transmit nal_cb [%p] private [%p] cookie [%p] hdr [%p] type [%d] global_nid [%u][%x] pid [%d] niov [%d] iov [%p] size [%d]\n", nal_cb, private, cookie, hdr, type, global_nid, global_nid, pid, niov, iov, size));

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("portals_hdr:: dest_nid [%lu], src_nid [%lu]\n", hdr->dest_nid, hdr->src_nid));

	if (!nal_data) {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("no nal_data\n"));
		return(LGMNAL_STATUS_FAIL);
	} else {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("nal_data [%p]\n", nal_data));
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


	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("Calling gm_send_to_peer port [%p] buffer [%p] gmsize [%d] msize [%d] global_nid [%u][%x] local_nid[%d] stxd [%p]\n",
			nal_data->gm_port, stxd->buffer, stxd->gmsize, tot_size, global_nid, global_nid, local_nid, stxd));
	LGMNAL_GM_LOCK(nal_data);
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, stxd->gmsize, tot_size, GM_LOW_PRIORITY, local_nid, lgmnal_small_tx_done, (void*)stxd);
	
	LGMNAL_GM_UNLOCK(nal_data);
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("done\n"));
		
	return(PTL_OK);
}


void 
lgmnal_small_tx_done(gm_port_t *gm_port, void *context, gm_status_t status)
{
	lgmnal_stxd_t	*stxd = (lgmnal_stxd_t*)context;
	lib_msg_t	*cookie = stxd->cookie;
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)stxd->nal_data;
	nal_cb_t	*nal_cb = nal_data->nal_cb;

	if (!stxd) {
		LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("send completion event for unknown stxd\n"));
		return;
	}
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Result of send stxd [%p] is [%s]\n", stxd, lgmnal_gm_error(status)));
	/* TO DO figure out which sends are worth retrying and get a send token to retry */
	if (lib_finalize(nal_cb, stxd, cookie) != PTL_OK) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Call to lib_finalize failed for stxd [%p]\n", stxd));
	}
	lgmnal_return_stxd(nal_data, stxd);
	return;
}


void 
lgmnal_large_tx1_done(gm_port_t *gm_port, void *context, gm_status_t status)
{

}

/*
 *	Begin a large transmit
 */
int
lgmnal_large_transmit1(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr, int type,
	ptl_nid_t global_nid, ptl_pid_t pid, unsigned int niov, struct iovec *iov, int size)
{

	lgmnal_data_t	*nal_data;
	lgmnal_stxd_t	*stxd = NULL;
	void		*buffer = NULL;
	lgmnal_msghdr_t	*msghdr = NULL;
	unsigned int	local_nid;
	int		mlen = 0;	/* the size of the init message data */


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_large_transmit1 nal_cb [%p] private [%p], cookie [%p] hdr [%p], type [%d] global_nid [%u], pid [%d], 
					niov [%d], iov [%p], size [%d]\n",
					nal_cb, private, cookie, hdr, type, global_nid, pid, niov, iov, size));

	if (nal_cb)
		nal_data = (lgmnal_data_t*)nal_cb->nal_data;
	else  {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("no nal_cb.\n"));
		return(LGMNAL_STATUS_FAIL);
	}
	

	/*
	 *	TO DO large transmit uses stxd. Should it have control descriptor?
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
	buffer += sizeof(lgmnal_msghdr_t);
	mlen = sizeof(lgmnal_msghdr_t);


	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing  portals hdr at [%p]\n", buffer));

	gm_bcopy(hdr, buffer, sizeof(ptl_hdr_t));
	buffer += sizeof(ptl_hdr_t);
	mlen += sizeof(ptl_hdr_t); 

	/*
	 *	Store the iovs in the stxd for we can get them later
	 *	in large_transmit2
	 */
	LGMNAL_PRINT(LGMNAL_DEBUG_V, ("Copying iov [%p] to [%p]\n", iov, stxd->iov));
	gm_bcopy(iov, stxd->iov, niov*sizeof(struct iovec));
	stxd->niov = niov;
	
	/*
 	 *	Send the init message to the target
	 */
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("sending mlen [%d]\n", mlen));
	LGMNAL_GM_LOCK(nal_data);
	gm_send_to_peer_with_callback(nal_data->gm_port, stxd->buffer, stxd->gmsize, mlen, GM_LOW_PRIORITY, local_nid, lgmnal_large_tx1_done, (void*)stxd);
	LGMNAL_GM_UNLOCK(nal_data);
	
	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("done\n"));
		
	return(PTL_OK);
}




EXPORT_SYMBOL(lgmnal_requeue_rxbuffer);
EXPORT_SYMBOL(lgmnal_badrx_message);
EXPORT_SYMBOL(lgmnal_large_tx1_done);
EXPORT_SYMBOL(lgmnal_large_transmit1);
EXPORT_SYMBOL(lgmnal_small_receive1);
EXPORT_SYMBOL(lgmnal_small_receive2);
EXPORT_SYMBOL(lgmnal_receive_thread);
EXPORT_SYMBOL(lgmnal_small_transmit);
EXPORT_SYMBOL(lgmnal_small_tx_done);
