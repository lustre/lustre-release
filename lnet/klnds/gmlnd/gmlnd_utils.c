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
gmnal_is_rxthread(gmnal_data_t *nal_data)
{
	int i;
	for (i=0; i<num_rx_threads; i++) {
		if (nal_data->rxthread_pid[i] == current->pid)
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
gmnal_alloc_txd(gmnal_data_t *nal_data)
{
	int ntx= 0, nstx= 0, nrxt_stx= 0,
	    nltx= 0, i = 0;
	gmnal_stxd_t	*txd = NULL;
	gmnal_ltxd_t	*ltxd = NULL;
	void	*txbuffer = NULL;

	CDEBUG(D_TRACE, "gmnal_alloc_small tx\n");

	GMNAL_GM_LOCK(nal_data);
	/*
	 *	total number of transmit tokens
	 */
	ntx = gm_num_send_tokens(nal_data->gm_port);
	GMNAL_GM_UNLOCK(nal_data);
	CDEBUG(D_INFO, "total number of send tokens available is [%d]\n", ntx);
	
	/*
 	 *	allocate a number for small sends
	 * 	num_stxds from gmnal_module.c
	 */
	nstx = num_stxds;
	/*
	 *	give that number plus 1 to the receive threads
	 */
        nrxt_stx = nstx + 1;

	/*
	 *	give the rest for gm_gets
	 */
	nltx = ntx - (nrxt_stx + nstx);
	if (nltx < 1) {
		CDEBUG(D_ERROR, "No tokens available for large messages\n");
		return(GMNAL_STATUS_FAIL);
	}


	/*
	 * A semaphore is initialised with the 
	 * number of transmit tokens available.
	 * To get a stxd, acquire the token semaphore.
 	 * this decrements the available token count
	 * (if no tokens you block here, someone returning a 
	 * stxd will release the semaphore and wake you)
	 * When token is obtained acquire the spinlock 
	 * to manipulate the list
	 */
	GMNAL_TXD_TOKEN_INIT(nal_data, nstx);
	GMNAL_TXD_LOCK_INIT(nal_data);
	GMNAL_RXT_TXD_TOKEN_INIT(nal_data, nrxt_stx);
	GMNAL_RXT_TXD_LOCK_INIT(nal_data);
	GMNAL_LTXD_TOKEN_INIT(nal_data, nltx);
	GMNAL_LTXD_LOCK_INIT(nal_data);
	
	for (i=0; i<=nstx; i++) {
		PORTAL_ALLOC(txd, sizeof(gmnal_stxd_t));
		if (!txd) {
			CDEBUG(D_ERROR, "Failed to malloc txd [%d]\n", i);
			return(GMNAL_STATUS_NOMEM);
		}
		GMNAL_GM_LOCK(nal_data);
		txbuffer = gm_dma_malloc(nal_data->gm_port, 
					 GMNAL_SMALL_MSG_SIZE(nal_data));
		GMNAL_GM_UNLOCK(nal_data);
		if (!txbuffer) {
			CDEBUG(D_ERROR, "Failed to gm_dma_malloc txbuffer [%d],
			       size [%d]\n", i, 
			       GMNAL_SMALL_MSG_SIZE(nal_data));
			PORTAL_FREE(txd, sizeof(gmnal_stxd_t));
			return(GMNAL_STATUS_FAIL);
		}
		txd->buffer = txbuffer;
		txd->buffer_size = GMNAL_SMALL_MSG_SIZE(nal_data);
		txd->gm_size = gm_min_size_for_length(txd->buffer_size);
		txd->nal_data = (struct _gmnal_data_t*)nal_data;
                txd->rxt = 0;

		txd->next = nal_data->stxd;
		nal_data->stxd = txd;
		CDEBUG(D_INFO, "Registered txd [%p] with buffer [%p], 
		       size [%d]\n", txd, txd->buffer, txd->buffer_size);
	}

	for (i=0; i<=nrxt_stx; i++) {
		PORTAL_ALLOC(txd, sizeof(gmnal_stxd_t));
		if (!txd) {
			CDEBUG(D_ERROR, "Failed to malloc txd [%d]\n", i);
			return(GMNAL_STATUS_NOMEM);
		}
		GMNAL_GM_LOCK(nal_data);
		txbuffer = gm_dma_malloc(nal_data->gm_port, 
					 GMNAL_SMALL_MSG_SIZE(nal_data));
		GMNAL_GM_UNLOCK(nal_data);
		if (!txbuffer) {
			CDEBUG(D_ERROR, "Failed to gm_dma_malloc txbuffer [%d],
			       size [%d]\n", i, 
			       GMNAL_SMALL_MSG_SIZE(nal_data));
			PORTAL_FREE(txd, sizeof(gmnal_stxd_t));
			return(GMNAL_STATUS_FAIL);
		}
		txd->buffer = txbuffer;
		txd->buffer_size = GMNAL_SMALL_MSG_SIZE(nal_data);
		txd->gm_size = gm_min_size_for_length(txd->buffer_size);
		txd->nal_data = (struct _gmnal_data_t*)nal_data;
                txd->rxt = 1;

		txd->next = nal_data->rxt_stxd;
		nal_data->rxt_stxd = txd;
		CDEBUG(D_INFO, "Registered txd [%p] with buffer [%p], 
		       size [%d]\n", txd, txd->buffer, txd->buffer_size);
	}

	/*
	 *	string together large tokens
	 */
	for (i=0; i<=nltx ; i++) {
		PORTAL_ALLOC(ltxd, sizeof(gmnal_ltxd_t));
		ltxd->next = nal_data->ltxd;
		nal_data->ltxd = ltxd;
	}
	return(GMNAL_STATUS_OK);
}

/*	Free the list of wired and gm_registered small tx buffers and 
 *	the tx descriptors that go along with them.
 */
void
gmnal_free_txd(gmnal_data_t *nal_data)
{
	gmnal_stxd_t *txd = nal_data->stxd, *_txd = NULL;
	gmnal_ltxd_t *ltxd = NULL, *_ltxd = NULL;

	CDEBUG(D_TRACE, "gmnal_free_small tx\n");

	while(txd) {
		CDEBUG(D_INFO, "Freeing txd [%p] with buffer [%p], 
		       size [%d]\n", txd, txd->buffer, txd->buffer_size);
		_txd = txd;
		txd = txd->next;
		GMNAL_GM_LOCK(nal_data);
		gm_dma_free(nal_data->gm_port, _txd->buffer);
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(_txd, sizeof(gmnal_stxd_t));
	}
        txd = nal_data->rxt_stxd;
	while(txd) {
		CDEBUG(D_INFO, "Freeing txd [%p] with buffer [%p], 
		       size [%d]\n", txd, txd->buffer, txd->buffer_size);
		_txd = txd;
		txd = txd->next;
		GMNAL_GM_LOCK(nal_data);
		gm_dma_free(nal_data->gm_port, _txd->buffer);
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(_txd, sizeof(gmnal_stxd_t));
	}
	ltxd = nal_data->ltxd;
	while(txd) {
		_ltxd = ltxd;
		ltxd = ltxd->next;
		PORTAL_FREE(_ltxd, sizeof(gmnal_ltxd_t));
	}
	
	return;
}


/*
 *	Get a txd from the list
 *	This get us a wired and gm_registered small tx buffer.
 *	This implicitly gets us a send token also.
 */
gmnal_stxd_t *
gmnal_get_stxd(gmnal_data_t *nal_data, int block)
{

	gmnal_stxd_t	*txd = NULL;
	pid_t		pid = current->pid;


	CDEBUG(D_TRACE, "gmnal_get_stxd nal_data [%p] block[%d] pid [%d]\n", 
	       nal_data, block, pid);

	if (gmnal_is_rxthread(nal_data)) {
                CDEBUG(D_INFO, "RXTHREAD Attempting to get token\n");
		GMNAL_RXT_TXD_GETTOKEN(nal_data);
	        GMNAL_RXT_TXD_LOCK(nal_data);
	        txd = nal_data->rxt_stxd;
		nal_data->rxt_stxd = txd->next;
	        GMNAL_RXT_TXD_UNLOCK(nal_data);
	        CDEBUG(D_INFO, "RXTHREAD got [%p], head is [%p]\n", 
		       txd, nal_data->rxt_stxd);
                txd->kniov = 0;
                txd->rxt = 1;
        } else {
	        if (block) {
                        CDEBUG(D_INFO, "Attempting to get token\n");
		        GMNAL_TXD_GETTOKEN(nal_data);
                        CDEBUG(D_PORTALS, "Got token\n");
	        } else {
		        if (GMNAL_TXD_TRYGETTOKEN(nal_data)) {
			        CDEBUG(D_ERROR, "can't get token\n");
			        return(NULL);
		        }
	        }
	        GMNAL_TXD_LOCK(nal_data);
	        txd = nal_data->stxd;
		nal_data->stxd = txd->next;
	        GMNAL_TXD_UNLOCK(nal_data);
	        CDEBUG(D_INFO, "got [%p], head is [%p]\n", txd, 
		       nal_data->stxd);
                txd->kniov = 0;
        }       /* general txd get */
	return(txd);
}

/*
 *	Return a txd to the list
 */
void
gmnal_return_stxd(gmnal_data_t *nal_data, gmnal_stxd_t *txd)
{
	CDEBUG(D_TRACE, "nal_data [%p], txd[%p] rxt[%d]\n", nal_data, 
	       txd, txd->rxt);

        /*
         *      this transmit descriptor is 
         *      for the rxthread
         */
        if (txd->rxt) {
	        GMNAL_RXT_TXD_LOCK(nal_data);
	        txd->next = nal_data->rxt_stxd;
	        nal_data->rxt_stxd = txd;
	        GMNAL_RXT_TXD_UNLOCK(nal_data);
	        GMNAL_RXT_TXD_RETURNTOKEN(nal_data);
                CDEBUG(D_INFO, "Returned stxd to rxthread list\n");
        } else {
	        GMNAL_TXD_LOCK(nal_data);
	        txd->next = nal_data->stxd;
	        nal_data->stxd = txd;
	        GMNAL_TXD_UNLOCK(nal_data);
	        GMNAL_TXD_RETURNTOKEN(nal_data);
                CDEBUG(D_INFO, "Returned stxd to general list\n");
        }
	return;
}


/*
 *	Get a large transmit descriptor from the free list
 *	This implicitly gets us a transmit  token .
 *	always wait for one.
 */
gmnal_ltxd_t *
gmnal_get_ltxd(gmnal_data_t *nal_data)
{

	gmnal_ltxd_t	*ltxd = NULL;

	CDEBUG(D_TRACE, "nal_data [%p]\n", nal_data);

	GMNAL_LTXD_GETTOKEN(nal_data);
	GMNAL_LTXD_LOCK(nal_data);
	ltxd = nal_data->ltxd;
	nal_data->ltxd = ltxd->next;
	GMNAL_LTXD_UNLOCK(nal_data);
	CDEBUG(D_INFO, "got [%p], head is [%p]\n", ltxd, nal_data->ltxd);
	return(ltxd);
}

/*
 *	Return an ltxd to the list
 */
void
gmnal_return_ltxd(gmnal_data_t *nal_data, gmnal_ltxd_t *ltxd)
{
	CDEBUG(D_TRACE, "nal_data [%p], ltxd[%p]\n", nal_data, ltxd);

	GMNAL_LTXD_LOCK(nal_data);
	ltxd->next = nal_data->ltxd;
	nal_data->ltxd = ltxd;
	GMNAL_LTXD_UNLOCK(nal_data);
	GMNAL_LTXD_RETURNTOKEN(nal_data);
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
gmnal_alloc_srxd(gmnal_data_t *nal_data)
{
	int nrx = 0, nsrx = 0, i = 0;
	gmnal_srxd_t	*rxd = NULL;
	void	*rxbuffer = NULL;

	CDEBUG(D_TRACE, "gmnal_alloc_small rx\n");

	GMNAL_GM_LOCK(nal_data);
	nrx = gm_num_receive_tokens(nal_data->gm_port);
	GMNAL_GM_UNLOCK(nal_data);
	CDEBUG(D_INFO, "total number of receive tokens available is [%d]\n", 
	       nrx);
	
	nsrx = nrx/2;
	nsrx = 12;
	/*
	 *	make the number of rxds twice our total
	 *	number of stxds plus 1
	 */
	nsrx = num_stxds*2 + 2;

	CDEBUG(D_INFO, "Allocated [%d] receive tokens to small messages\n", 
	       nsrx);


	GMNAL_GM_LOCK(nal_data);
	nal_data->srxd_hash = gm_create_hash(gm_hash_compare_ptrs, 
					     gm_hash_hash_ptr, 0, 0, nsrx, 0);
	GMNAL_GM_UNLOCK(nal_data);
	if (!nal_data->srxd_hash) {
			CDEBUG(D_ERROR, "Failed to create hash table\n");
			return(GMNAL_STATUS_NOMEM);
	}

	GMNAL_RXD_TOKEN_INIT(nal_data, nsrx);
	GMNAL_RXD_LOCK_INIT(nal_data);

	for (i=0; i<=nsrx; i++) {
		PORTAL_ALLOC(rxd, sizeof(gmnal_srxd_t));
		if (!rxd) {
			CDEBUG(D_ERROR, "Failed to malloc rxd [%d]\n", i);
			return(GMNAL_STATUS_NOMEM);
		}
#if 0
		PORTAL_ALLOC(rxbuffer, GMNAL_SMALL_MSG_SIZE(nal_data));
		if (!rxbuffer) {
			CDEBUG(D_ERROR, "Failed to malloc rxbuffer [%d], 
			       size [%d]\n", i, 
			       GMNAL_SMALL_MSG_SIZE(nal_data));
			PORTAL_FREE(rxd, sizeof(gmnal_srxd_t));
			return(GMNAL_STATUS_FAIL);
		}
		CDEBUG(D_NET, "Calling gm_register_memory with port [%p] 
		       rxbuffer [%p], size [%d]\n", nal_data->gm_port, 
		       rxbuffer, GMNAL_SMALL_MSG_SIZE(nal_data));
		GMNAL_GM_LOCK(nal_data);
		gm_status = gm_register_memory(nal_data->gm_port, rxbuffer, 
					       GMNAL_SMALL_MSG_SIZE(nal_data));
		GMNAL_GM_UNLOCK(nal_data);
		if (gm_status != GM_SUCCESS) {
			CDEBUG(D_ERROR, "gm_register_memory failed buffer [%p],
			       index [%d]\n", rxbuffer, i);
			switch(gm_status) {
				case(GM_FAILURE):
					CDEBUG(D_ERROR, "GM_FAILURE\n");
				break;
				case(GM_PERMISSION_DENIED):
					CDEBUG(D_ERROR, "PERMISSION_DENIED\n");
				break;
				case(GM_INVALID_PARAMETER):
					CDEBUG(D_ERROR, "INVALID_PARAMETER\n");
				break;
				default:
					CDEBUG(D_ERROR, "Unknown error[%d]\n", 
					       gm_status);
				break;
				
			}
			return(GMNAL_STATUS_FAIL);
		}
#else
		GMNAL_GM_LOCK(nal_data);
		rxbuffer = gm_dma_malloc(nal_data->gm_port, 
					 GMNAL_SMALL_MSG_SIZE(nal_data));
		GMNAL_GM_UNLOCK(nal_data);
		if (!rxbuffer) {
			CDEBUG(D_ERROR, "Failed to gm_dma_malloc rxbuffer [%d],
			       size [%d]\n", i, 
			       GMNAL_SMALL_MSG_SIZE(nal_data));
			PORTAL_FREE(rxd, sizeof(gmnal_srxd_t));
			return(GMNAL_STATUS_FAIL);
		}
#endif
		
		rxd->buffer = rxbuffer;
		rxd->size = GMNAL_SMALL_MSG_SIZE(nal_data);
		rxd->gmsize = gm_min_size_for_length(rxd->size);

		if (gm_hash_insert(nal_data->srxd_hash, 
				   (void*)rxbuffer, (void*)rxd)) {

			CDEBUG(D_ERROR, "failed to create hash entry rxd[%p] 
			       for rxbuffer[%p]\n", rxd, rxbuffer);
			return(GMNAL_STATUS_FAIL);
		}

		rxd->next = nal_data->srxd;
		nal_data->srxd = rxd;
		CDEBUG(D_INFO, "Registered rxd [%p] with buffer [%p], 
		       size [%d]\n", rxd, rxd->buffer, rxd->size);
	}

	return(GMNAL_STATUS_OK);
}



/*	Free the list of wired and gm_registered small rx buffers and the 
 *	rx descriptors that go along with them.
 */
void
gmnal_free_srxd(gmnal_data_t *nal_data)
{
	gmnal_srxd_t *rxd = nal_data->srxd, *_rxd = NULL;

	CDEBUG(D_TRACE, "gmnal_free_small rx\n");

	while(rxd) {
		CDEBUG(D_INFO, "Freeing rxd [%p] buffer [%p], size [%d]\n",
		       rxd, rxd->buffer, rxd->size);
		_rxd = rxd;
		rxd = rxd->next;

#if 0
		GMNAL_GM_LOCK(nal_data);
		gm_deregister_memory(nal_data->gm_port, _rxd->buffer, 
				     _rxd->size);
		GMNAL_GM_UNLOCK(nal_data);
		PORTAL_FREE(_rxd->buffer, GMNAL_SMALL_RXBUFFER_SIZE);
#else
		GMNAL_GM_LOCK(nal_data);
		gm_dma_free(nal_data->gm_port, _rxd->buffer);
		GMNAL_GM_UNLOCK(nal_data);
#endif
		PORTAL_FREE(_rxd, sizeof(gmnal_srxd_t));
	}
	return;
}


/*
 *	Get a rxd from the free list
 *	This get us a wired and gm_registered small rx buffer.
 *	This implicitly gets us a receive token also.
 */
gmnal_srxd_t *
gmnal_get_srxd(gmnal_data_t *nal_data, int block)
{

	gmnal_srxd_t	*rxd = NULL;
	CDEBUG(D_TRACE, "nal_data [%p] block [%d]\n", nal_data, block);

	if (block) {
		GMNAL_RXD_GETTOKEN(nal_data);
	} else {
		if (GMNAL_RXD_TRYGETTOKEN(nal_data)) {
			CDEBUG(D_INFO, "gmnal_get_srxd Can't get token\n");
			return(NULL);
		}
	}
	GMNAL_RXD_LOCK(nal_data);
	rxd = nal_data->srxd;
	if (rxd)
		nal_data->srxd = rxd->next;
	GMNAL_RXD_UNLOCK(nal_data);
	CDEBUG(D_INFO, "got [%p], head is [%p]\n", rxd, nal_data->srxd);
	return(rxd);
}

/*
 *	Return an rxd to the list
 */
void
gmnal_return_srxd(gmnal_data_t *nal_data, gmnal_srxd_t *rxd)
{
	CDEBUG(D_TRACE, "nal_data [%p], rxd[%p]\n", nal_data, rxd);

	GMNAL_RXD_LOCK(nal_data);
	rxd->next = nal_data->srxd;
	nal_data->srxd = rxd;
	GMNAL_RXD_UNLOCK(nal_data);
	GMNAL_RXD_RETURNTOKEN(nal_data);
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
gmnal_rxbuffer_to_srxd(gmnal_data_t *nal_data, void *rxbuffer)
{
	gmnal_srxd_t	*srxd = NULL;
	CDEBUG(D_TRACE, "nal_data [%p], rxbuffer [%p]\n", nal_data, rxbuffer);
	srxd = gm_hash_find(nal_data->srxd_hash, rxbuffer);
	CDEBUG(D_INFO, "srxd is [%p]\n", srxd);
	return(srxd);
}


void
gmnal_stop_rxthread(gmnal_data_t *nal_data)
{
	int 	delay = 30;



	CDEBUG(D_TRACE, "Attempting to stop rxthread nal_data [%p]\n", 
	        nal_data);
	
	nal_data->rxthread_stop_flag = GMNAL_THREAD_STOP;

	gmnal_remove_rxtwe(nal_data);
	/*
	 *	kick the thread 
	 */
	up(&nal_data->rxtwe_wait);

	while(nal_data->rxthread_flag != GMNAL_THREAD_RESET && delay--) {
		CDEBUG(D_INFO, "gmnal_stop_rxthread sleeping\n");
                gmnal_yield(1);
		up(&nal_data->rxtwe_wait);
	}

	if (nal_data->rxthread_flag != GMNAL_THREAD_RESET) {
		CDEBUG(D_ERROR, "I don't know how to wake the thread\n");
	} else {
		CDEBUG(D_INFO, "rx thread seems to have stopped\n");
	}
}

void
gmnal_stop_ctthread(gmnal_data_t *nal_data)
{
	int 	delay = 15;



	CDEBUG(D_TRACE, "Attempting to stop ctthread nal_data [%p]\n", 
	       nal_data);
	
	nal_data->ctthread_flag = GMNAL_THREAD_STOP;
	GMNAL_GM_LOCK(nal_data);
	gm_set_alarm(nal_data->gm_port, &nal_data->ctthread_alarm, 10, 
		     NULL, NULL);
	GMNAL_GM_UNLOCK(nal_data);

	while(nal_data->ctthread_flag == GMNAL_THREAD_STOP && delay--) {
		CDEBUG(D_INFO, "gmnal_stop_ctthread sleeping\n");
                gmnal_yield(1);
	}

	if (nal_data->ctthread_flag == GMNAL_THREAD_STOP) {
		CDEBUG(D_ERROR, "I DON'T KNOW HOW TO WAKE THE THREAD\n");
	} else {
		CDEBUG(D_INFO, "CT THREAD SEEMS TO HAVE STOPPED\n");
	}
}



char * 
gmnal_gm_error(gm_status_t status)
{
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
gmnal_is_small_msg(gmnal_data_t *nal_data, int niov, struct iovec *iov, 
		    int len)
{

	CDEBUG(D_TRACE, "len [%d] limit[%d]\n", len, 
	       GMNAL_SMALL_MSG_SIZE(nal_data));

	if ((len + sizeof(ptl_hdr_t) + sizeof(gmnal_msghdr_t)) 
	             < GMNAL_SMALL_MSG_SIZE(nal_data)) {

		CDEBUG(D_INFO, "Yep, small message\n");
		return(1);
	} else {
		CDEBUG(D_ERROR, "No, not small message\n");
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
gmnal_add_rxtwe(gmnal_data_t *nal_data, gm_recv_t *recv)
{
	gmnal_rxtwe_t	*we = NULL;

	CDEBUG(D_NET, "adding entry to list\n");

	PORTAL_ALLOC(we, sizeof(gmnal_rxtwe_t));
	if (!we) {
		CDEBUG(D_ERROR, "failed to malloc\n");
		return(GMNAL_STATUS_FAIL);
	}
	we->buffer = gm_ntohp(recv->buffer);
	we->snode = (int)gm_ntoh_u16(recv->sender_node_id);
	we->sport = (int)gm_ntoh_u8(recv->sender_port_id);
	we->type = (int)gm_ntoh_u8(recv->type);
	we->length = (int)gm_ntohl(recv->length);

	spin_lock(&nal_data->rxtwe_lock);
	if (nal_data->rxtwe_tail) {
		nal_data->rxtwe_tail->next = we;
	} else {
		nal_data->rxtwe_head = we;
		nal_data->rxtwe_tail = we;
	}
	nal_data->rxtwe_tail = we;
	spin_unlock(&nal_data->rxtwe_lock);

	up(&nal_data->rxtwe_wait);
	return(GMNAL_STATUS_OK);
}

void
gmnal_remove_rxtwe(gmnal_data_t *nal_data)
{
	gmnal_rxtwe_t	*_we, *we = nal_data->rxtwe_head;

	CDEBUG(D_NET, "removing all work list entries\n");

	spin_lock(&nal_data->rxtwe_lock);
	CDEBUG(D_NET, "Got lock\n");
	while (we) {
		_we = we;
		we = we->next;
		PORTAL_FREE(_we, sizeof(gmnal_rxtwe_t));
	}
	spin_unlock(&nal_data->rxtwe_lock);
	nal_data->rxtwe_head = NULL;
	nal_data->rxtwe_tail = NULL;
}

gmnal_rxtwe_t *
gmnal_get_rxtwe(gmnal_data_t *nal_data)
{
	gmnal_rxtwe_t	*we = NULL;

	CDEBUG(D_NET, "Getting entry to list\n");

	do  {
		down(&nal_data->rxtwe_wait);
		if (nal_data->rxthread_stop_flag == GMNAL_THREAD_STOP) {
			/*
			 *	time to stop
			 * 	TO DO some one free the work entries	
			 */
			return(NULL);
		}
		spin_lock(&nal_data->rxtwe_lock);
		if (nal_data->rxtwe_head) {
			CDEBUG(D_WARNING, "Got a work entry\n");
			we = nal_data->rxtwe_head;
			nal_data->rxtwe_head = we->next;
			if (!nal_data->rxtwe_head)
				nal_data->rxtwe_tail = NULL;
		} else {
			CDEBUG(D_WARNING, "woken but no work\n");
		}
		spin_unlock(&nal_data->rxtwe_lock);
	} while (!we);

	CDEBUG(D_WARNING, "Returning we[%p]\n", we);
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
gmnal_start_kernel_threads(gmnal_data_t *nal_data)
{

	int	threads = 0;
	/*
 	 *	the alarm is used to wake the caretaker thread from 
	 *	gm_unknown call (sleeping) to exit it.
	 */
	CDEBUG(D_NET, "Initializing caretaker thread alarm and flag\n");
	gm_initialize_alarm(&nal_data->ctthread_alarm);
	nal_data->ctthread_flag = GMNAL_THREAD_RESET;


	CDEBUG(D_INFO, "Starting caretaker thread\n");
	nal_data->ctthread_pid = 
	         kernel_thread(gmnal_ct_thread, (void*)nal_data, 0);
	if (nal_data->ctthread_pid <= 0) {
		CDEBUG(D_ERROR, "Caretaker thread failed to start\n");
		return(GMNAL_STATUS_FAIL);
	}

	while (nal_data->rxthread_flag != GMNAL_THREAD_RESET) {
		gmnal_yield(1);
		CDEBUG(D_INFO, "Waiting for caretaker thread signs of life\n");
	}

	CDEBUG(D_INFO, "caretaker thread has started\n");


	/*
 	 *	Now start a number of receiver threads
	 *	these treads get work to do from the caretaker (ct) thread
	 */
	nal_data->rxthread_flag = GMNAL_THREAD_RESET;
	nal_data->rxthread_stop_flag = GMNAL_THREAD_RESET;

	for (threads=0; threads<NRXTHREADS; threads++)
		nal_data->rxthread_pid[threads] = -1;
	spin_lock_init(&nal_data->rxtwe_lock);
	spin_lock_init(&nal_data->rxthread_flag_lock);
	sema_init(&nal_data->rxtwe_wait, 0);
	nal_data->rxtwe_head = NULL;
	nal_data->rxtwe_tail = NULL;
        /*
         *      If the default number of receive threades isn't
         *      modified at load time, then start one thread per cpu
         */
        if (num_rx_threads == -1)
                num_rx_threads = smp_num_cpus;
	CDEBUG(D_INFO, "Starting [%d] receive threads\n", num_rx_threads);
	for (threads=0; threads<num_rx_threads; threads++) {
		nal_data->rxthread_pid[threads] = 
		       kernel_thread(gmnal_rx_thread, (void*)nal_data, 0);
		if (nal_data->rxthread_pid[threads] <= 0) {
			CDEBUG(D_ERROR, "Receive thread failed to start\n");
			gmnal_stop_rxthread(nal_data);
			gmnal_stop_ctthread(nal_data);
			return(GMNAL_STATUS_FAIL);
		}
	}

	for (;;) {
		spin_lock(&nal_data->rxthread_flag_lock);
		if (nal_data->rxthread_flag == GMNAL_RXTHREADS_STARTED) {
			spin_unlock(&nal_data->rxthread_flag_lock);
			break;
		}
		spin_unlock(&nal_data->rxthread_flag_lock);
		gmnal_yield(1);
	}

	CDEBUG(D_INFO, "receive threads seem to have started\n");

	return(GMNAL_STATUS_OK);
}

EXPORT_SYMBOL(gmnal_yield);
EXPORT_SYMBOL(gmnal_alloc_srxd);
EXPORT_SYMBOL(gmnal_get_srxd);
EXPORT_SYMBOL(gmnal_return_srxd);
EXPORT_SYMBOL(gmnal_free_srxd);
EXPORT_SYMBOL(gmnal_alloc_txd);
EXPORT_SYMBOL(gmnal_get_stxd);
EXPORT_SYMBOL(gmnal_return_stxd);
EXPORT_SYMBOL(gmnal_free_txd);
EXPORT_SYMBOL(gmnal_rxbuffer_to_srxd);
EXPORT_SYMBOL(gmnal_rxevent);
EXPORT_SYMBOL(gmnal_gm_error);
EXPORT_SYMBOL(gmnal_stop_ctthread);
EXPORT_SYMBOL(gmnal_add_rxtwe);
EXPORT_SYMBOL(gmnal_get_rxtwe);
