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
 *	All utilities required by lgmanl
 */

#include "gmnal.h"

/*
 *	Am I one of the gmnal rxthreads ?
 */
int
gmnal_is_rxthread(gmnal_ni_t *gmnalni)
{
	int i;
	for (i=0; i<num_rx_threads; i++) {
		if (gmnalni->gmni_rxthread_pid[i] == current->pid)
			return(1);
	}
	return(0);
}


/*
 *	Allocate tx descriptors/tokens (large and small)
 *	allocate a number of small tx buffers and register with GM
 *	so they are wired and set up for DMA. This is a costly operation.
 *	Also allocate a corrosponding descriptor to keep track of 
 *	the buffer.
 *	Put all small descriptors on singly linked list to be available to send 
 *	function.
 *	Allocate the rest of the available tx tokens for large messages. These will be
 *	used to do gm_gets in gmnal_copyiov	
 */
int
gmnal_alloc_txd(gmnal_ni_t *gmnalni)
{
	int           ntx;
        int           nstx;
        int           nrxt_stx;
        int           i;
	gmnal_stxd_t *txd;
	void	     *txbuffer;

	CDEBUG(D_TRACE, "gmnal_alloc_small tx\n");

	spin_lock(&gmnalni->gmni_gm_lock);
	/*
	 *	total number of transmit tokens
	 */
	ntx = gm_num_send_tokens(gmnalni->gmni_port);
	spin_unlock(&gmnalni->gmni_gm_lock);
	CDEBUG(D_NET, "total number of send tokens available is [%d]\n", ntx);

	/*
	 *	allocate a number for small sends
	 *	num_stxds from gmnal_module.c
	 */
	nstx = num_stxds;
	/*
	 *	give the rest to the receive threads
	 */
        nrxt_stx = num_stxds + 1;

        if (nstx + nrxt_stx > ntx) {
                CERROR ("Asked for %d + %d tx credits, but only %d available\n",
                        nstx, nrxt_stx, ntx);
                return -ENOMEM;
        }
        
	/* A semaphore is initialised with the number of transmit tokens
	 * available.  To get a stxd, acquire the token semaphore.  this
	 * decrements the available token count (if no tokens you block here,
	 * someone returning a stxd will release the semaphore and wake you)
	 * When token is obtained acquire the spinlock to manipulate the
	 * list */
	sema_init(&gmnalni->gmni_stxd_token, nstx);
	spin_lock_init(&gmnalni->gmni_stxd_lock);

	sema_init(&gmnalni->gmni_rxt_stxd_token, nrxt_stx);
	spin_lock_init(&gmnalni->gmni_rxt_stxd_lock);

	for (i=0; i<=nstx; i++) {
		PORTAL_ALLOC(txd, sizeof(*txd));
		if (txd == NULL) {
			CERROR("Failed to malloc txd [%d]\n", i);
			return -ENOMEM;
		}
		spin_lock(&gmnalni->gmni_gm_lock);
		txbuffer = gm_dma_malloc(gmnalni->gmni_port,
					 gmnalni->gmni_small_msg_size);
		spin_unlock(&gmnalni->gmni_gm_lock);
		if (txbuffer == NULL) {
			CERROR("Failed to gm_dma_malloc txbuffer [%d], "
			       "size [%d]\n", i, gmnalni->gmni_small_msg_size);
			PORTAL_FREE(txd, sizeof(*txd));
			return -ENOMEM;
		}
		txd->tx_buffer = txbuffer;
		txd->tx_buffer_size = gmnalni->gmni_small_msg_size;
		txd->tx_gm_size = gm_min_size_for_length(txd->tx_buffer_size);
		txd->tx_gmni = gmnalni;
                txd->tx_rxt = 0;

		txd->tx_next = gmnalni->gmni_stxd;
		gmnalni->gmni_stxd = txd;
		CDEBUG(D_NET, "Registered txd [%p] with buffer [%p], "
		       "size [%d]\n", txd, txd->tx_buffer, txd->tx_buffer_size);
	}

	for (i=0; i<=nrxt_stx; i++) {
		PORTAL_ALLOC(txd, sizeof(gmnal_stxd_t));
		if (!txd) {
			CERROR("Failed to malloc txd [%d]\n", i);
			return -ENOMEM;
		}
		spin_lock(&gmnalni->gmni_gm_lock);
		txbuffer = gm_dma_malloc(gmnalni->gmni_port, 
					 gmnalni->gmni_small_msg_size);
		spin_unlock(&gmnalni->gmni_gm_lock);
		if (!txbuffer) {
			CERROR("Failed to gm_dma_malloc txbuffer [%d],"
			       " size [%d]\n",i, gmnalni->gmni_small_msg_size);
			PORTAL_FREE(txd, sizeof(gmnal_stxd_t));
			return -ENOMEM;
		}
		txd->tx_buffer = txbuffer;
		txd->tx_buffer_size = gmnalni->gmni_small_msg_size;
		txd->tx_gm_size = gm_min_size_for_length(txd->tx_buffer_size);
		txd->tx_gmni = gmnalni;
                txd->tx_rxt = 1;

		txd->tx_next = gmnalni->gmni_rxt_stxd;
		gmnalni->gmni_rxt_stxd = txd;
		CDEBUG(D_NET, "Registered txd [%p] with buffer [%p], "
		       "size [%d]\n", txd, txd->tx_buffer, txd->tx_buffer_size);
	}

	return 0;
}

/*	Free the list of wired and gm_registered small tx buffers and 
 *	the tx descriptors that go along with them.
 */
void
gmnal_free_txd(gmnal_ni_t *gmnalni)
{
	gmnal_stxd_t *txd;
        gmnal_stxd_t *_txd;

	CDEBUG(D_TRACE, "gmnal_free_small tx\n");

        txd = gmnalni->gmni_stxd;
	while(txd != NULL) {
		CDEBUG(D_NET, "Freeing txd [%p] with buffer [%p], "
		       "size [%d]\n", txd, txd->tx_buffer, txd->tx_buffer_size);
		_txd = txd;
		txd = txd->tx_next;
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_dma_free(gmnalni->gmni_port, _txd->tx_buffer);
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(_txd, sizeof(gmnal_stxd_t));
	}

        txd = gmnalni->gmni_rxt_stxd;
	while(txd) {
		CDEBUG(D_NET, "Freeing txd [%p] with buffer [%p], "
		       "size [%d]\n", txd, txd->tx_buffer, txd->tx_buffer_size);
		_txd = txd;
		txd = txd->tx_next;
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_dma_free(gmnalni->gmni_port, _txd->tx_buffer);
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(_txd, sizeof(gmnal_stxd_t));
	}
}


/*
 *	Get a txd from the list
 *	This get us a wired and gm_registered small tx buffer.
 *	This implicitly gets us a send token also.
 */
gmnal_stxd_t *
gmnal_get_stxd(gmnal_ni_t *gmnalni, int block)
{

	gmnal_stxd_t	*txd = NULL;
	pid_t		pid = current->pid;


	CDEBUG(D_TRACE, "gmnal_get_stxd gmnalni [%p] block[%d] pid [%d]\n", 
	       gmnalni, block, pid);

	if (gmnal_is_rxthread(gmnalni)) {
                CDEBUG(D_NET, "RXTHREAD Attempting to get token\n");
		down(&gmnalni->gmni_rxt_stxd_token);
	        spin_lock(&gmnalni->gmni_rxt_stxd_lock);
	        txd = gmnalni->gmni_rxt_stxd;
		gmnalni->gmni_rxt_stxd = txd->tx_next;
	        spin_unlock(&gmnalni->gmni_rxt_stxd_lock);
	        CDEBUG(D_NET, "RXTHREAD got [%p], head is [%p]\n", 
		       txd, gmnalni->gmni_rxt_stxd);
                txd->tx_kniov = 0;
                txd->tx_rxt = 1;
        } else {
	        if (block) {
                        CDEBUG(D_NET, "Attempting to get token\n");
		        down(&gmnalni->gmni_stxd_token);
                        CDEBUG(D_PORTALS, "Got token\n");
	        } else {
		        if (down_trylock(&gmnalni->gmni_stxd_token)) {
			        CERROR("can't get token\n");
			        return(NULL);
		        }
	        }
	        spin_lock(&gmnalni->gmni_stxd_lock);
	        txd = gmnalni->gmni_stxd;
		gmnalni->gmni_stxd = txd->tx_next;
	        spin_unlock(&gmnalni->gmni_stxd_lock);
	        CDEBUG(D_NET, "got [%p], head is [%p]\n", txd,
		       gmnalni->gmni_stxd);
                txd->tx_kniov = 0;
        }       /* general txd get */
	return(txd);
}

/*
 *	Return a txd to the list
 */
void
gmnal_return_stxd(gmnal_ni_t *gmnalni, gmnal_stxd_t *txd)
{
	CDEBUG(D_TRACE, "gmnalni [%p], txd[%p] rxt[%d]\n", gmnalni,
	       txd, txd->tx_rxt);

        /*
         *      this transmit descriptor is 
         *      for the rxthread
         */
        if (txd->tx_rxt) {
	        spin_lock(&gmnalni->gmni_rxt_stxd_lock);
	        txd->tx_next = gmnalni->gmni_rxt_stxd;
	        gmnalni->gmni_rxt_stxd = txd;
	        spin_unlock(&gmnalni->gmni_rxt_stxd_lock);
	        up(&gmnalni->gmni_rxt_stxd_token);
                CDEBUG(D_NET, "Returned stxd to rxthread list\n");
        } else {
	        spin_lock(&gmnalni->gmni_stxd_lock);
	        txd->tx_next = gmnalni->gmni_stxd;
	        gmnalni->gmni_stxd = txd;
	        spin_unlock(&gmnalni->gmni_stxd_lock);
	        up(&gmnalni->gmni_stxd_token);
                CDEBUG(D_NET, "Returned stxd to general list\n");
        }
	return;
}


/*
 *	allocate a number of small rx buffers and register with GM
 *	so they are wired and set up for DMA. This is a costly operation.
 *	Also allocate a corrosponding descriptor to keep track of 
 *	the buffer.
 *	Put all descriptors on singly linked list to be available to 
 *	receive thread.
 */
int
gmnal_alloc_srxd(gmnal_ni_t *gmnalni)
{
	int nrx = 0, nsrx = 0, i = 0;
	gmnal_srxd_t	*rxd = NULL;
	void	*rxbuffer = NULL;

	CDEBUG(D_TRACE, "gmnal_alloc_small rx\n");

	spin_lock(&gmnalni->gmni_gm_lock);
	nrx = gm_num_receive_tokens(gmnalni->gmni_port);
	spin_unlock(&gmnalni->gmni_gm_lock);
	CDEBUG(D_NET, "total number of receive tokens available is [%d]\n",
	       nrx);

	nsrx = nrx/2;
	nsrx = 12;
	/*
	 *	make the number of rxds twice our total
	 *	number of stxds plus 1
	 */
	nsrx = num_stxds*2 + 2;

	CDEBUG(D_NET, "Allocated [%d] receive tokens to small messages\n",
	       nsrx);


	spin_lock(&gmnalni->gmni_gm_lock);
	gmnalni->gmni_srxd_hash = gm_create_hash(gm_hash_compare_ptrs, 
                                                  gm_hash_hash_ptr, 0, 0, nsrx, 0);
	spin_unlock(&gmnalni->gmni_gm_lock);
	if (!gmnalni->gmni_srxd_hash) {
			CERROR("Failed to create hash table\n");
			return -ENOMEM;
	}

	for (i=0; i<=nsrx; i++) {
		PORTAL_ALLOC(rxd, sizeof(gmnal_srxd_t));
		if (!rxd) {
			CERROR("Failed to malloc rxd [%d]\n", i);
			return -ENOMEM;
		}

		spin_lock(&gmnalni->gmni_gm_lock);
		rxbuffer = gm_dma_malloc(gmnalni->gmni_port, 
					 gmnalni->gmni_small_msg_size);
		spin_unlock(&gmnalni->gmni_gm_lock);
		if (!rxbuffer) {
			CERROR("Failed to gm_dma_malloc rxbuffer [%d], "
			       "size [%d]\n",i ,gmnalni->gmni_small_msg_size);
			PORTAL_FREE(rxd, sizeof(gmnal_srxd_t));
			return -ENOMEM;
		}

		rxd->rx_buffer = rxbuffer;
		rxd->rx_size = gmnalni->gmni_small_msg_size;
		rxd->rx_gmsize = gm_min_size_for_length(rxd->rx_size);

		if (gm_hash_insert(gmnalni->gmni_srxd_hash,
				   (void*)rxbuffer, (void*)rxd)) {

			CERROR("failed to create hash entry rxd[%p] "
			       "for rxbuffer[%p]\n", rxd, rxbuffer);
			return -ENOMEM;
		}

		rxd->rx_next = gmnalni->gmni_srxd;
		gmnalni->gmni_srxd = rxd;
		CDEBUG(D_NET, "Registered rxd [%p] with buffer [%p], "
		       "size [%d]\n", rxd, rxd->rx_buffer, rxd->rx_size);
	}

	return 0;
}



/*	Free the list of wired and gm_registered small rx buffers and the 
 *	rx descriptors that go along with them.
 */
void
gmnal_free_srxd(gmnal_ni_t *gmnalni)
{
	gmnal_srxd_t *rxd = gmnalni->gmni_srxd, *_rxd = NULL;

	CDEBUG(D_TRACE, "gmnal_free_small rx\n");

	while(rxd) {
		CDEBUG(D_NET, "Freeing rxd [%p] buffer [%p], size [%d]\n",
		       rxd, rxd->rx_buffer, rxd->rx_size);
		_rxd = rxd;
		rxd = rxd->rx_next;

		spin_lock(&gmnalni->gmni_gm_lock);
		gm_dma_free(gmnalni->gmni_port, _rxd->rx_buffer);
		spin_unlock(&gmnalni->gmni_gm_lock);

		PORTAL_FREE(_rxd, sizeof(gmnal_srxd_t));
	}
	return;
}


/*
 *	Given a pointer to a srxd find 
 *	the relevant descriptor for it
 *	This is done by searching a hash
 *	list that is created when the srxd's 
 *	are created
 */
gmnal_srxd_t *
gmnal_rxbuffer_to_srxd(gmnal_ni_t *gmnalni, void *rxbuffer)
{
	gmnal_srxd_t	*srxd = NULL;
	CDEBUG(D_TRACE, "gmnalni [%p], rxbuffer [%p]\n", gmnalni, rxbuffer);
	srxd = gm_hash_find(gmnalni->gmni_srxd_hash, rxbuffer);
	CDEBUG(D_NET, "srxd is [%p]\n", srxd);
	return(srxd);
}


void
gmnal_stop_rxthread(gmnal_ni_t *gmnalni)
{
	int 	delay = 30;



	CDEBUG(D_TRACE, "Attempting to stop rxthread gmnalni [%p]\n", 
	        gmnalni);
	
	gmnalni->gmni_rxthread_stop_flag = GMNAL_THREAD_STOP;

	gmnal_remove_rxtwe(gmnalni);
	/*
	 *	kick the thread 
	 */
	up(&gmnalni->gmni_rxtwe_wait);

	while(gmnalni->gmni_rxthread_flag != GMNAL_THREAD_RESET && delay--) {
		CDEBUG(D_NET, "gmnal_stop_rxthread sleeping\n");
                gmnal_yield(1);
		up(&gmnalni->gmni_rxtwe_wait);
	}

	if (gmnalni->gmni_rxthread_flag != GMNAL_THREAD_RESET) {
		CERROR("I don't know how to wake the thread\n");
	} else {
		CDEBUG(D_NET, "rx thread seems to have stopped\n");
	}
}

void
gmnal_stop_ctthread(gmnal_ni_t *gmnalni)
{
	int 	delay = 15;



	CDEBUG(D_TRACE, "Attempting to stop ctthread gmnalni [%p]\n", 
	       gmnalni);
	
	gmnalni->gmni_ctthread_flag = GMNAL_THREAD_STOP;
	spin_lock(&gmnalni->gmni_gm_lock);
	gm_set_alarm(gmnalni->gmni_port, &gmnalni->gmni_ctthread_alarm, 10, 
		     NULL, NULL);
	spin_unlock(&gmnalni->gmni_gm_lock);

	while(gmnalni->gmni_ctthread_flag == GMNAL_THREAD_STOP && delay--) {
		CDEBUG(D_NET, "gmnal_stop_ctthread sleeping\n");
                gmnal_yield(1);
	}

	if (gmnalni->gmni_ctthread_flag == GMNAL_THREAD_STOP) {
		CERROR("I DON'T KNOW HOW TO WAKE THE THREAD\n");
	} else {
		CDEBUG(D_NET, "CT THREAD SEEMS TO HAVE STOPPED\n");
	}
}



char * 
gmnal_gm_error(gm_status_t status)
{
	return(gm_strerror(status));

	switch(status) {
		case(GM_SUCCESS):
			return("SUCCESS");
  		case(GM_FAILURE):
			return("FAILURE");
  		case(GM_INPUT_BUFFER_TOO_SMALL):
			return("INPUT_BUFFER_TOO_SMALL");
  		case(GM_OUTPUT_BUFFER_TOO_SMALL):
			return("OUTPUT_BUFFER_TOO_SMALL");
  		case(GM_TRY_AGAIN ):
			return("TRY_AGAIN");
  		case(GM_BUSY):
			return("BUSY");
  		case(GM_MEMORY_FAULT):
			return("MEMORY_FAULT");
  		case(GM_INTERRUPTED):
			return("INTERRUPTED");
  		case(GM_INVALID_PARAMETER):
			return("INVALID_PARAMETER");
  		case(GM_OUT_OF_MEMORY):
			return("OUT_OF_MEMORY");
  		case(GM_INVALID_COMMAND):
			return("INVALID_COMMAND");
  		case(GM_PERMISSION_DENIED):
			return("PERMISSION_DENIED");
  		case(GM_INTERNAL_ERROR):
			return("INTERNAL_ERROR");
  		case(GM_UNATTACHED):
			return("UNATTACHED");
  		case(GM_UNSUPPORTED_DEVICE):
			return("UNSUPPORTED_DEVICE");
  		case(GM_SEND_TIMED_OUT):
			return("GM_SEND_TIMEDOUT");
  		case(GM_SEND_REJECTED):
			return("GM_SEND_REJECTED");
  		case(GM_SEND_TARGET_PORT_CLOSED):
			return("GM_SEND_TARGET_PORT_CLOSED");
  		case(GM_SEND_TARGET_NODE_UNREACHABLE):
			return("GM_SEND_TARGET_NODE_UNREACHABLE");
  		case(GM_SEND_DROPPED):
			return("GM_SEND_DROPPED");
  		case(GM_SEND_PORT_CLOSED):
			return("GM_SEND_PORT_CLOSED");
  		case(GM_NODE_ID_NOT_YET_SET):
			return("GM_NODE_ID_NOT_YET_SET");
  		case(GM_STILL_SHUTTING_DOWN):
			return("GM_STILL_SHUTTING_DOWN");
  		case(GM_CLONE_BUSY):
			return("GM_CLONE_BUSY");
  		case(GM_NO_SUCH_DEVICE):
			return("GM_NO_SUCH_DEVICE");
  		case(GM_ABORTED):
			return("GM_ABORTED");
  		case(GM_INCOMPATIBLE_LIB_AND_DRIVER):
			return("GM_INCOMPATIBLE_LIB_AND_DRIVER");
  		case(GM_UNTRANSLATED_SYSTEM_ERROR):
			return("GM_UNTRANSLATED_SYSTEM_ERROR");
  		case(GM_ACCESS_DENIED):
			return("GM_ACCESS_DENIED");


/*
 *	These ones are in the docs but aren't in the header file 
  		case(GM_DEV_NOT_FOUND):
			return("GM_DEV_NOT_FOUND");
  		case(GM_INVALID_PORT_NUMBER):
			return("GM_INVALID_PORT_NUMBER");
  		case(GM_UC_ERROR):
			return("GM_US_ERROR");
  		case(GM_PAGE_TABLE_FULL):
			return("GM_PAGE_TABLE_FULL");
  		case(GM_MINOR_OVERFLOW):
			return("GM_MINOR_OVERFLOW");
  		case(GM_SEND_ORPHANED):
			return("GM_SEND_ORPHANED");
  		case(GM_HARDWARE_FAULT):
			return("GM_HARDWARE_FAULT");
  		case(GM_DATA_CORRUPTED):
			return("GM_DATA_CORRUPTED");
  		case(GM_TIMED_OUT):
			return("GM_TIMED_OUT");
  		case(GM_USER_ERROR):
			return("GM_USER_ERROR");
  		case(GM_NO_MATCH):
			return("GM_NOMATCH");
  		case(GM_NOT_SUPPORTED_IN_KERNEL):
			return("GM_NOT_SUPPORTED_IN_KERNEL");
  		case(GM_NOT_SUPPORTED_ON_ARCH):
			return("GM_NOT_SUPPORTED_ON_ARCH");
  		case(GM_PTE_REF_CNT_OVERFLOW):
			return("GM_PTR_REF_CNT_OVERFLOW");
  		case(GM_NO_DRIVER_SUPPORT):
			return("GM_NO_DRIVER_SUPPORT");
  		case(GM_FIRMWARE_NOT_RUNNING):
			return("GM_FIRMWARE_NOT_RUNNING");

 *	These ones are in the docs but aren't in the header file 
 */
		default:
			return("UNKNOWN GM ERROR CODE");
	}
}


char *
gmnal_rxevent(gm_recv_event_t	*ev)
{
	short	event;
	event = GM_RECV_EVENT_TYPE(ev);
	switch(event) {
  		case(GM_NO_RECV_EVENT):
			return("GM_NO_RECV_EVENT");
  		case(GM_SENDS_FAILED_EVENT):
			return("GM_SEND_FAILED_EVENT");
  		case(GM_ALARM_EVENT):
			return("GM_ALARM_EVENT");
  		case(GM_SENT_EVENT):
			return("GM_SENT_EVENT");
  		case(_GM_SLEEP_EVENT):
			return("_GM_SLEEP_EVENT");
  		case(GM_RAW_RECV_EVENT):
			return("GM_RAW_RECV_EVENT");
  		case(GM_BAD_SEND_DETECTED_EVENT):
			return("GM_BAD_SEND_DETECTED_EVENT");
  		case(GM_SEND_TOKEN_VIOLATION_EVENT):
			return("GM_SEND_TOKEN_VIOLATION_EVENT");
  		case(GM_RECV_TOKEN_VIOLATION_EVENT):
			return("GM_RECV_TOKEN_VIOLATION_EVENT");
  		case(GM_BAD_RECV_TOKEN_EVENT):
			return("GM_BAD_RECV_TOKEN_EVENT");
  		case(GM_ALARM_VIOLATION_EVENT):
			return("GM_ALARM_VIOLATION_EVENT");
  		case(GM_RECV_EVENT):
			return("GM_RECV_EVENT");
  		case(GM_HIGH_RECV_EVENT):
			return("GM_HIGH_RECV_EVENT");
  		case(GM_PEER_RECV_EVENT):
			return("GM_PEER_RECV_EVENT");
  		case(GM_HIGH_PEER_RECV_EVENT):
			return("GM_HIGH_PEER_RECV_EVENT");
  		case(GM_FAST_RECV_EVENT):
			return("GM_FAST_RECV_EVENT");
  		case(GM_FAST_HIGH_RECV_EVENT):
			return("GM_FAST_HIGH_RECV_EVENT");
  		case(GM_FAST_PEER_RECV_EVENT):
			return("GM_FAST_PEER_RECV_EVENT");
  		case(GM_FAST_HIGH_PEER_RECV_EVENT):
			return("GM_FAST_HIGH_PEER_RECV_EVENT");
  		case(GM_REJECTED_SEND_EVENT):
			return("GM_REJECTED_SEND_EVENT");
  		case(GM_ORPHANED_SEND_EVENT):
			return("GM_ORPHANED_SEND_EVENT");
  		case(GM_BAD_RESEND_DETECTED_EVENT):
			return("GM_BAD_RESEND_DETETED_EVENT");
  		case(GM_DROPPED_SEND_EVENT):
			return("GM_DROPPED_SEND_EVENT");
  		case(GM_BAD_SEND_VMA_EVENT):
			return("GM_BAD_SEND_VMA_EVENT");
  		case(GM_BAD_RECV_VMA_EVENT):
			return("GM_BAD_RECV_VMA_EVENT");
  		case(_GM_FLUSHED_ALARM_EVENT):
			return("GM_FLUSHED_ALARM_EVENT");
  		case(GM_SENT_TOKENS_EVENT):
			return("GM_SENT_TOKENS_EVENTS");
  		case(GM_IGNORE_RECV_EVENT):
			return("GM_IGNORE_RECV_EVENT");
  		case(GM_ETHERNET_RECV_EVENT):
			return("GM_ETHERNET_RECV_EVENT");
  		case(GM_NEW_NO_RECV_EVENT):
			return("GM_NEW_NO_RECV_EVENT");
  		case(GM_NEW_SENDS_FAILED_EVENT):
			return("GM_NEW_SENDS_FAILED_EVENT");
  		case(GM_NEW_ALARM_EVENT):
			return("GM_NEW_ALARM_EVENT");
  		case(GM_NEW_SENT_EVENT):
			return("GM_NEW_SENT_EVENT");
  		case(_GM_NEW_SLEEP_EVENT):
			return("GM_NEW_SLEEP_EVENT");
  		case(GM_NEW_RAW_RECV_EVENT):
			return("GM_NEW_RAW_RECV_EVENT");
  		case(GM_NEW_BAD_SEND_DETECTED_EVENT):
			return("GM_NEW_BAD_SEND_DETECTED_EVENT");
  		case(GM_NEW_SEND_TOKEN_VIOLATION_EVENT):
			return("GM_NEW_SEND_TOKEN_VIOLATION_EVENT");
  		case(GM_NEW_RECV_TOKEN_VIOLATION_EVENT):
			return("GM_NEW_RECV_TOKEN_VIOLATION_EVENT");
  		case(GM_NEW_BAD_RECV_TOKEN_EVENT):
			return("GM_NEW_BAD_RECV_TOKEN_EVENT");
  		case(GM_NEW_ALARM_VIOLATION_EVENT):
			return("GM_NEW_ALARM_VIOLATION_EVENT");
  		case(GM_NEW_RECV_EVENT):
			return("GM_NEW_RECV_EVENT");
  		case(GM_NEW_HIGH_RECV_EVENT):
			return("GM_NEW_HIGH_RECV_EVENT");
  		case(GM_NEW_PEER_RECV_EVENT):
			return("GM_NEW_PEER_RECV_EVENT");
  		case(GM_NEW_HIGH_PEER_RECV_EVENT):
			return("GM_NEW_HIGH_PEER_RECV_EVENT");
  		case(GM_NEW_FAST_RECV_EVENT):
			return("GM_NEW_FAST_RECV_EVENT");
  		case(GM_NEW_FAST_HIGH_RECV_EVENT):
			return("GM_NEW_FAST_HIGH_RECV_EVENT");
  		case(GM_NEW_FAST_PEER_RECV_EVENT):
			return("GM_NEW_FAST_PEER_RECV_EVENT");
  		case(GM_NEW_FAST_HIGH_PEER_RECV_EVENT):
			return("GM_NEW_FAST_HIGH_PEER_RECV_EVENT");
  		case(GM_NEW_REJECTED_SEND_EVENT):
			return("GM_NEW_REJECTED_SEND_EVENT");
  		case(GM_NEW_ORPHANED_SEND_EVENT):
			return("GM_NEW_ORPHANED_SEND_EVENT");
  		case(_GM_NEW_PUT_NOTIFICATION_EVENT):
			return("_GM_NEW_PUT_NOTIFICATION_EVENT");
  		case(GM_NEW_FREE_SEND_TOKEN_EVENT):
			return("GM_NEW_FREE_SEND_TOKEN_EVENT");
  		case(GM_NEW_FREE_HIGH_SEND_TOKEN_EVENT):
			return("GM_NEW_FREE_HIGH_SEND_TOKEN_EVENT");
  		case(GM_NEW_BAD_RESEND_DETECTED_EVENT):
			return("GM_NEW_BAD_RESEND_DETECTED_EVENT");
  		case(GM_NEW_DROPPED_SEND_EVENT):
			return("GM_NEW_DROPPED_SEND_EVENT");
  		case(GM_NEW_BAD_SEND_VMA_EVENT):
			return("GM_NEW_BAD_SEND_VMA_EVENT");
  		case(GM_NEW_BAD_RECV_VMA_EVENT):
			return("GM_NEW_BAD_RECV_VMA_EVENT");
  		case(_GM_NEW_FLUSHED_ALARM_EVENT):
			return("GM_NEW_FLUSHED_ALARM_EVENT");
  		case(GM_NEW_SENT_TOKENS_EVENT):
			return("GM_NEW_SENT_TOKENS_EVENT");
  		case(GM_NEW_IGNORE_RECV_EVENT):
			return("GM_NEW_IGNORE_RECV_EVENT");
  		case(GM_NEW_ETHERNET_RECV_EVENT):
			return("GM_NEW_ETHERNET_RECV_EVENT");
		default:
			return("Unknown Recv event");
#if 0
  		case(/* _GM_PUT_NOTIFICATION_EVENT */
  		case(/* GM_FREE_SEND_TOKEN_EVENT */
  		case(/* GM_FREE_HIGH_SEND_TOKEN_EVENT */
#endif
	}
}


void
gmnal_yield(int delay)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(delay);
}

int
gmnal_is_small_msg(gmnal_ni_t *gmnalni, int niov, struct iovec *iov, 
		    int len)
{

	CDEBUG(D_TRACE, "len [%d] limit[%d]\n", len, 
	       gmnalni->gmni_small_msg_size);

	if ((len + sizeof(ptl_hdr_t) + sizeof(gmnal_msghdr_t)) 
	             < gmnalni->gmni_small_msg_size) {

		CDEBUG(D_NET, "Yep, small message\n");
		return(1);
	} else {
		CERROR("No, not small message\n");
		/*
		 *	could be made up of lots of little ones !
		 */
		return(0);
	}

}

/* 
 *	extract info from the receive event.
 *	Have to do this before the next call to gm_receive
 *	Deal with all endian stuff here.
 *	Then stick work entry on list where rxthreads
 *	can get it to complete the receive
 */
int
gmnal_add_rxtwe(gmnal_ni_t *gmnalni, gm_recv_t *recv)
{
	gmnal_rxtwe_t	*we = NULL;

	CDEBUG(D_NET, "adding entry to list\n");

	PORTAL_ALLOC(we, sizeof(gmnal_rxtwe_t));
	if (!we) {
		CERROR("failed to malloc\n");
		return -ENOMEM;
	}
	we->buffer = gm_ntohp(recv->buffer);
	we->snode = (int)gm_ntoh_u16(recv->sender_node_id);
	we->sport = (int)gm_ntoh_u8(recv->sender_port_id);
	we->type = (int)gm_ntoh_u8(recv->type);
	we->length = (int)gm_ntohl(recv->length);

	spin_lock(&gmnalni->gmni_rxtwe_lock);
	if (gmnalni->gmni_rxtwe_tail) {
		gmnalni->gmni_rxtwe_tail->next = we;
	} else {
		gmnalni->gmni_rxtwe_head = we;
		gmnalni->gmni_rxtwe_tail = we;
	}
	gmnalni->gmni_rxtwe_tail = we;
	spin_unlock(&gmnalni->gmni_rxtwe_lock);

	up(&gmnalni->gmni_rxtwe_wait);
	return 0;
}

void
gmnal_remove_rxtwe(gmnal_ni_t *gmnalni)
{
	gmnal_rxtwe_t	*_we, *we = gmnalni->gmni_rxtwe_head;

	CDEBUG(D_NET, "removing all work list entries\n");

	spin_lock(&gmnalni->gmni_rxtwe_lock);
	CDEBUG(D_NET, "Got lock\n");
	while (we) {
		_we = we;
		we = we->next;
		PORTAL_FREE(_we, sizeof(gmnal_rxtwe_t));
	}
	spin_unlock(&gmnalni->gmni_rxtwe_lock);
	gmnalni->gmni_rxtwe_head = NULL;
	gmnalni->gmni_rxtwe_tail = NULL;
}

gmnal_rxtwe_t *
gmnal_get_rxtwe(gmnal_ni_t *gmnalni)
{
	gmnal_rxtwe_t	*we = NULL;

	CDEBUG(D_NET, "Getting entry to list\n");

	do  {
		while(down_interruptible(&gmnalni->gmni_rxtwe_wait) != 0)
                        /* do nothing */;

		if (gmnalni->gmni_rxthread_stop_flag == GMNAL_THREAD_STOP) {
			/*
			 *	time to stop
			 *	TO DO some one free the work entries
			 */
			return(NULL);
		}

		spin_lock(&gmnalni->gmni_rxtwe_lock);
		if (gmnalni->gmni_rxtwe_head) {
			CDEBUG(D_NET, "Got a work entry\n");
			we = gmnalni->gmni_rxtwe_head;
			gmnalni->gmni_rxtwe_head = we->next;
			if (!gmnalni->gmni_rxtwe_head)
				gmnalni->gmni_rxtwe_tail = NULL;
		} else {
			CWARN("woken but no work\n");
		}

		spin_unlock(&gmnalni->gmni_rxtwe_lock);
	} while (!we);

	CDEBUG(D_NET, "Returning we[%p]\n", we);
	return(we);
}


/*
 *	Start the caretaker thread and a number of receiver threads
 *	The caretaker thread gets events from the gm library.
 *	It passes receive events to the receiver threads via a work list.
 *	It processes other events itself in gm_unknown. These will be
 *	callback events or sleeps.
 */
int
gmnal_start_kernel_threads(gmnal_ni_t *gmnalni)
{

	int	threads = 0;
	/*
 	 *	the alarm is used to wake the caretaker thread from 
	 *	gm_unknown call (sleeping) to exit it.
	 */
	CDEBUG(D_NET, "Initializing caretaker thread alarm and flag\n");
	gm_initialize_alarm(&gmnalni->gmni_ctthread_alarm);
	gmnalni->gmni_ctthread_flag = GMNAL_THREAD_RESET;


	CDEBUG(D_NET, "Starting caretaker thread\n");
	gmnalni->gmni_ctthread_pid = 
	         kernel_thread(gmnal_ct_thread, (void*)gmnalni, 0);
	if (gmnalni->gmni_ctthread_pid <= 0) {
		CERROR("Caretaker thread failed to start\n");
		return -ENOMEM;
	}

	while (gmnalni->gmni_rxthread_flag != GMNAL_THREAD_RESET) {
		gmnal_yield(1);
		CDEBUG(D_NET, "Waiting for caretaker thread signs of life\n");
	}

	CDEBUG(D_NET, "caretaker thread has started\n");


	/*
 	 *	Now start a number of receiver threads
	 *	these treads get work to do from the caretaker (ct) thread
	 */
	gmnalni->gmni_rxthread_flag = GMNAL_THREAD_RESET;
	gmnalni->gmni_rxthread_stop_flag = GMNAL_THREAD_RESET;

	for (threads=0; threads<NRXTHREADS; threads++)
		gmnalni->gmni_rxthread_pid[threads] = -1;
	spin_lock_init(&gmnalni->gmni_rxtwe_lock);
	spin_lock_init(&gmnalni->gmni_rxthread_flag_lock);
	sema_init(&gmnalni->gmni_rxtwe_wait, 0);
	gmnalni->gmni_rxtwe_head = NULL;
	gmnalni->gmni_rxtwe_tail = NULL;
        /*
         *      If the default number of receive threades isn't
         *      modified at load time, then start one thread per cpu
         */
        if (num_rx_threads == -1)
                num_rx_threads = smp_num_cpus;
	CDEBUG(D_NET, "Starting [%d] receive threads\n", num_rx_threads);
	for (threads=0; threads<num_rx_threads; threads++) {
		gmnalni->gmni_rxthread_pid[threads] = 
		       kernel_thread(gmnal_rx_thread, (void*)gmnalni, 0);
		if (gmnalni->gmni_rxthread_pid[threads] <= 0) {
			CERROR("Receive thread failed to start\n");
			gmnal_stop_rxthread(gmnalni);
			gmnal_stop_ctthread(gmnalni);
			return -ENOMEM;
		}
	}

	for (;;) {
		spin_lock(&gmnalni->gmni_rxthread_flag_lock);
		if (gmnalni->gmni_rxthread_flag == GMNAL_RXTHREADS_STARTED) {
			spin_unlock(&gmnalni->gmni_rxthread_flag_lock);
			break;
		}
		spin_unlock(&gmnalni->gmni_rxthread_flag_lock);
		gmnal_yield(1);
	}

	CDEBUG(D_NET, "receive threads seem to have started\n");

	return 0;
}
