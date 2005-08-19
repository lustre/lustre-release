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
	gmnal_ni_t		*gmnalni;
	gm_recv_event_t		*rxevent = NULL;
	gm_recv_t		*recv = NULL;

	if (!arg) {
		CDEBUG(D_NET, "NO gmnalni. Exiting\n");
		return(-1);
	}

	gmnalni = (gmnal_ni_t*)arg;
	CDEBUG(D_NET, "gmnalni is [%p]\n", arg);

	sprintf(current->comm, "gmnal_ct");

	kportal_daemonize("gmnalctd");

	gmnalni->gmni_ctthread_flag = GMNAL_CTTHREAD_STARTED;

	spin_lock(&gmnalni->gmni_gm_lock);
	while(gmnalni->gmni_ctthread_flag == GMNAL_CTTHREAD_STARTED) {
		CDEBUG(D_NET, "waiting\n");
		rxevent = gm_blocking_receive_no_spin(gmnalni->gmni_port);
		if (gmnalni->gmni_ctthread_flag == GMNAL_THREAD_STOP) {
			CDEBUG(D_NET, "time to exit\n");
			break;
		}
		CDEBUG(D_NET, "got [%s]\n", gmnal_rxevent(rxevent));
		switch (GM_RECV_EVENT_TYPE(rxevent)) {

			case(GM_RECV_EVENT):
				CDEBUG(D_NET, "CTTHREAD:: GM_RECV_EVENT\n");
				recv = (gm_recv_t*)&rxevent->recv;
				spin_unlock(&gmnalni->gmni_gm_lock);
				gmnal_add_rxtwe(gmnalni, recv);
				spin_lock(&gmnalni->gmni_gm_lock);
				CDEBUG(D_NET, "CTTHREAD:: Added event to Q\n");
			break;
			case(_GM_SLEEP_EVENT):
				/*
				 *	Blocking receive above just returns
				 *	immediatly with _GM_SLEEP_EVENT
				 *	Don't know what this is
				 */
				CDEBUG(D_NET, "Sleeping in gm_unknown\n");
				spin_unlock(&gmnalni->gmni_gm_lock);
				gm_unknown(gmnalni->gmni_port, rxevent);
				spin_lock(&gmnalni->gmni_gm_lock);
				CDEBUG(D_NET, "Awake from gm_unknown\n");
				break;
				
			default:
				/*
				 *	Don't know what this is
				 *	gm_unknown will make sense of it
				 *	Should be able to do something with
				 *	FAST_RECV_EVENTS here.
				 */
				CDEBUG(D_NET, "Passing event to gm_unknown\n");
				spin_unlock(&gmnalni->gmni_gm_lock);
				gm_unknown(gmnalni->gmni_port, rxevent);
				spin_lock(&gmnalni->gmni_gm_lock);
				CDEBUG(D_NET, "Processed unknown event\n");
		}
	}
	spin_unlock(&gmnalni->gmni_gm_lock);
	gmnalni->gmni_ctthread_flag = GMNAL_THREAD_RESET;
	CDEBUG(D_NET, "thread gmnalni [%p] is exiting\n", gmnalni);

	return 0;
}


/*
 *	process a receive event
 */
int 
gmnal_rx_thread(void *arg)
{
        char                     name[16];
	gmnal_ni_t		*gmnalni;
	void			*buffer;
	gmnal_rxtwe_t		*we = NULL;
	int			rank;

	if (!arg) {
		CDEBUG(D_NET, "NO gmnalni. Exiting\n");
		return(-1);
	}

	gmnalni = (gmnal_ni_t*)arg;
	CDEBUG(D_NET, "gmnalni is [%p]\n", arg);

	for (rank=0; rank<num_rx_threads; rank++)
		if (gmnalni->gmni_rxthread_pid[rank] == current->pid)
			break;

	snprintf(name, sizeof(name), "gmnal_rx_%d", rank);
	kportal_daemonize(name);

	/*
	 * 	set 1 bit for each thread started
	 *	doesn't matter which bit
	 */
	spin_lock(&gmnalni->gmni_rxthread_flag_lock);
	if (gmnalni->gmni_rxthread_flag)
		gmnalni->gmni_rxthread_flag = gmnalni->gmni_rxthread_flag*2 + 1;
	else
		gmnalni->gmni_rxthread_flag = 1;
	CDEBUG(D_NET, "rxthread flag is [%ld]\n", gmnalni->gmni_rxthread_flag);
	spin_unlock(&gmnalni->gmni_rxthread_flag_lock);

	while(gmnalni->gmni_rxthread_stop_flag != GMNAL_THREAD_STOP) {
		CDEBUG(D_NET, "RXTHREAD:: Receive thread waiting\n");
		we = gmnal_get_rxtwe(gmnalni);
		if (!we) {
			CDEBUG(D_NET, "Receive thread time to exit\n");
			break;
		}

		buffer = we->buffer;
		switch(((gmnal_msghdr_t*)buffer)->gmm_type) {
		case(GMNAL_SMALL_MESSAGE):
			gmnal_pre_receive(gmnalni, we, GMNAL_SMALL_MESSAGE);
		break;
		default:
#warning better handling
			CERROR("Unsupported message type\n");
			gmnal_rx_bad(gmnalni, we);
		}
		PORTAL_FREE(we, sizeof(gmnal_rxtwe_t));
	}

	spin_lock(&gmnalni->gmni_rxthread_flag_lock);
	gmnalni->gmni_rxthread_flag/=2;
	CDEBUG(D_NET, "rxthread flag is [%ld]\n", gmnalni->gmni_rxthread_flag);
	spin_unlock(&gmnalni->gmni_rxthread_flag_lock);
	CDEBUG(D_NET, "thread gmnalni [%p] is exiting\n", gmnalni);

	return 0;
}



/*
 *	Start processing a small message receive
 *	Get here from gmnal_receive_thread
 *	Hand off to lib_parse, which calls cb_recv
 *	which hands back to gmnal_small_receive
 *	Deal with all endian stuff here.
 */
void
gmnal_pre_receive(gmnal_ni_t *gmnalni, gmnal_rxtwe_t *we, int gmnal_type)
{
	gmnal_srxd_t	*srxd = NULL;
	void		*buffer = NULL;
	gmnal_msghdr_t	*gmnal_msghdr;
	ptl_hdr_t	*portals_hdr;

	CDEBUG(D_NET, "gmnalni [%p], we[%p] type [%d]\n",
	       gmnalni, we, gmnal_type);

	buffer = we->buffer;

	gmnal_msghdr = (gmnal_msghdr_t*)buffer;
	portals_hdr = (ptl_hdr_t*)(buffer+sizeof(gmnal_msghdr_t));

	CDEBUG(D_NET, "rx_event:: Sender node [%d], Sender Port [%d], "
	       "type [%d], length [%d], buffer [%p]\n",
               we->snode, we->sport, we->type, we->length, buffer);
	CDEBUG(D_NET, "gmnal_msghdr:: Sender node [%u], magic [%d], "
	       "gmnal_type [%d]\n", gmnal_msghdr->gmm_sender_gmid,
	       gmnal_msghdr->gmm_magic, gmnal_msghdr->gmm_type);
	CDEBUG(D_NET, "portals_hdr:: Sender node ["LPD64"], "
	       "dest_node ["LPD64"]\n", portals_hdr->src_nid,
	       portals_hdr->dest_nid);

	/*
	 *	Get a receive descriptor for this message
	 */
	srxd = gmnal_rxbuffer_to_srxd(gmnalni, buffer);
	CDEBUG(D_NET, "Back from gmnal_rxbuffer_to_srxd\n");
	if (!srxd) {
		CERROR("Failed to get receive descriptor\n");
                LBUG();
	}

	srxd->rx_gmni = gmnalni;
	srxd->rx_type = gmnal_type;
	srxd->rx_nsiov = gmnal_msghdr->gmm_niov;
	srxd->rx_sender_gmid = gmnal_msghdr->gmm_sender_gmid;

	CDEBUG(D_PORTALS, "Calling lib_parse buffer is [%p]\n",
	       buffer+sizeof(gmnal_msghdr_t));

	(void)lib_parse(gmnalni->gmni_libnal, portals_hdr, srxd);
        /* Ignore error; we're connectionless */

        gmnal_rx_requeue_buffer(gmnalni, srxd);
}



/*
 *	After a receive has been processed, 
 *	hang out the receive buffer again.
 *	This implicitly returns a receive token.
 */
void
gmnal_rx_requeue_buffer(gmnal_ni_t *gmnalni, gmnal_srxd_t *srxd)
{
	CDEBUG(D_NET, "requeueing srxd[%p] gmnalni[%p]\n", srxd, gmnalni);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_provide_receive_buffer_with_tag(gmnalni->gmni_port, srxd->rx_buffer,
                                           srxd->rx_gmsize, GM_LOW_PRIORITY, 0 );
	spin_unlock(&gmnalni->gmni_gm_lock);
}


/*
 *	Handle a bad message
 *	A bad message is one we don't expect or can't interpret
 */
void
gmnal_rx_bad(gmnal_ni_t *gmnalni, gmnal_rxtwe_t *we)
{
        gmnal_srxd_t *srxd = gmnal_rxbuffer_to_srxd(gmnalni, 
                                                    we->buffer);
	if (srxd == NULL) {
		CERROR("Can't find a descriptor for this buffer\n");
		return;
	}

        gmnal_rx_requeue_buffer(gmnalni, srxd);
}



/*
 *	Start a small transmit. 
 *	Use the given send token (and wired transmit buffer).
 *	Copy headers to wired buffer and initiate gm_send from the wired buffer.
 *	The callback function informs when the send is complete.
 */
ptl_err_t
gmnal_small_tx(lib_nal_t *libnal, void *private, lib_msg_t *cookie,
		ptl_hdr_t *hdr, int type, ptl_nid_t nid,
		gmnal_stxd_t *stxd, int size)
{
	gmnal_ni_t	*gmnalni = (gmnal_ni_t*)libnal->libnal_data;
	void		*buffer = NULL;
	gmnal_msghdr_t	*msghdr = NULL;
	int		tot_size = 0;
	gm_status_t	gm_status = GM_SUCCESS;

	CDEBUG(D_NET, "gmnal_small_tx libnal [%p] private [%p] cookie [%p] "
	       "hdr [%p] type [%d] nid ["LPU64"] stxd [%p] "
	       "size [%d]\n", libnal, private, cookie, hdr, type,
	       nid, stxd, size);

	CDEBUG(D_NET, "portals_hdr:: dest_nid ["LPU64"], src_nid ["LPU64"]\n",
	       hdr->dest_nid, hdr->src_nid);

        LASSERT ((nid >> 32) == 0);
        LASSERT (gmnalni != NULL);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_status = gm_global_id_to_node_id(gmnalni->gmni_port, (__u32)nid, 
                                            &stxd->tx_gmlid);
	spin_unlock(&gmnalni->gmni_gm_lock);

	if (gm_status != GM_SUCCESS) {
		CERROR("Failed to obtain local id\n");
		return(PTL_FAIL);
	}

	CDEBUG(D_NET, "Local Node_id is [%u][%x]\n", 
               stxd->tx_gmlid, stxd->tx_gmlid);

        stxd->tx_nid = nid;
	stxd->tx_cookie = cookie;
	stxd->tx_type = GMNAL_SMALL_MESSAGE;
	stxd->tx_gm_priority = GM_LOW_PRIORITY;

	/*
	 *	Copy gmnal_msg_hdr and portals header to the transmit buffer
	 *	Then send the message, as the data has previously been copied in
	 *      (HP SFS 1380).
	 */
	buffer = stxd->tx_buffer;
	msghdr = (gmnal_msghdr_t*)buffer;

	msghdr->gmm_magic = GMNAL_MAGIC;
	msghdr->gmm_type = GMNAL_SMALL_MESSAGE;
	msghdr->gmm_sender_gmid = gmnalni->gmni_global_gmid;
	CDEBUG(D_NET, "processing msghdr at [%p]\n", buffer);

	buffer += sizeof(gmnal_msghdr_t);

	CDEBUG(D_NET, "processing  portals hdr at [%p]\n", buffer);
	gm_bcopy(hdr, buffer, sizeof(ptl_hdr_t));

	buffer += sizeof(ptl_hdr_t);

	CDEBUG(D_NET, "sending\n");
	tot_size = size+sizeof(ptl_hdr_t)+sizeof(gmnal_msghdr_t);
	stxd->tx_msg_size = tot_size;

	CDEBUG(D_NET, "Calling gm_send_to_peer port [%p] buffer [%p] "
	       "gmsize [%lu] msize [%d] nid ["LPU64"] local_gmid[%d] "
	       "stxd [%p]\n", gmnalni->gmni_port, stxd->tx_buffer, 
               stxd->tx_gm_size, stxd->tx_msg_size, nid, stxd->tx_gmlid, 
               stxd);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_send_to_peer_with_callback(gmnalni->gmni_port, stxd->tx_buffer,
				      stxd->tx_gm_size, stxd->tx_msg_size,
                                      stxd->tx_gm_priority, stxd->tx_gmlid,
				      gmnal_small_tx_callback, (void*)stxd);
	spin_unlock(&gmnalni->gmni_gm_lock);
	CDEBUG(D_NET, "done\n");

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
	lib_msg_t	*cookie = stxd->tx_cookie;
	gmnal_ni_t	*gmnalni = stxd->tx_gmni;
	lib_nal_t	*libnal = gmnalni->gmni_libnal;

	if (!stxd) {
		CDEBUG(D_NET, "send completion event for unknown stxd\n");
		return;
	}
	if (status != GM_SUCCESS)
		CERROR("Result of send stxd [%p] is [%s] to ["LPU64"]\n",
		       stxd, gmnal_gm_error(status), stxd->tx_nid);

	switch(status) {
		case(GM_SUCCESS):
		break;



		case(GM_SEND_DROPPED):
		/*
		 *	do a resend on the dropped ones
		 */
			CERROR("send stxd [%p] dropped, resending\n", context);
			spin_lock(&gmnalni->gmni_gm_lock);
			gm_send_to_peer_with_callback(gmnalni->gmni_port,
						      stxd->tx_buffer,
						      stxd->tx_gm_size,
						      stxd->tx_msg_size,
						      stxd->tx_gm_priority,
						      stxd->tx_gmlid,
						      gmnal_small_tx_callback,
						      context);
			spin_unlock(&gmnalni->gmni_gm_lock);
		return;
		case(GM_TIMED_OUT):
		case(GM_SEND_TIMED_OUT):
		/*
		 *	drop these ones
		 */
			CDEBUG(D_NET, "calling gm_drop_sends\n");
			spin_lock(&gmnalni->gmni_gm_lock);
			gm_drop_sends(gmnalni->gmni_port, stxd->tx_gm_priority, 
				      stxd->tx_gmlid, gm_port_id, 
				      gmnal_drop_sends_callback, context);
			spin_unlock(&gmnalni->gmni_gm_lock);

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
                gm_resume_sending(gmnalni->gmni_port, stxd->tx_gm_priority,
                                  stxd->tx_gmlid, gm_port_id,
                                  gmnal_resume_sending_callback, context);
                return;

	}

	gmnal_return_stxd(gmnalni, stxd);
	lib_finalize(libnal, stxd, cookie, PTL_OK);
	return;
}

/*
 *	After an error on the port
 *	call this to allow future sends to complete
 */
void gmnal_resume_sending_callback(struct gm_port *gm_port, void *context,
                                 gm_status_t status)
{
        gmnal_stxd_t    *stxd = (gmnal_stxd_t*)context;
        gmnal_ni_t     *gmnalni = stxd->tx_gmni;

        CDEBUG(D_NET, "status is [%d] context is [%p]\n", status, context);
        gmnal_return_stxd(gmnalni, stxd);
        lib_finalize(gmnalni->gmni_libnal, stxd, stxd->tx_cookie, PTL_FAIL);
        return;
}


void gmnal_drop_sends_callback(struct gm_port *gm_port, void *context, 
			        gm_status_t status)
{
	gmnal_stxd_t	*stxd = (gmnal_stxd_t*)context;
	gmnal_ni_t	*gmnalni = stxd->tx_gmni;

	CDEBUG(D_NET, "status is [%d] context is [%p]\n", status, context);
	if (status == GM_SUCCESS) {
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_send_to_peer_with_callback(gm_port, stxd->tx_buffer, 
					      stxd->tx_gm_size, 
                                              stxd->tx_msg_size, 
					      stxd->tx_gm_priority, 
					      stxd->tx_gmlid, 
					      gmnal_small_tx_callback, 
					      context);
		spin_unlock(&gmnalni->gmni_gm_lock);
	} else {
		CERROR("send_to_peer status for stxd [%p] is "
		       "[%d][%s]\n", stxd, status, gmnal_gm_error(status));
                /* Recycle the stxd */
		gmnal_return_stxd(gmnalni, stxd);
		lib_finalize(gmnalni->gmni_libnal, stxd, stxd->tx_cookie, PTL_FAIL);
	}

	return;
}


