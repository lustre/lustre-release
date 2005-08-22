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

gmnal_tx_t *
gmnal_alloc_tx (gmnal_ni_t *gmnalni) 
{
        gmnal_tx_t  *tx;
        void        *buffer;
        
        PORTAL_ALLOC(tx, sizeof(*tx));
        if (tx == NULL) {
                CERROR ("Failed to allocate tx\n");
                return NULL;
        }
        
        buffer = gm_dma_malloc(gmnalni->gmni_port, gmnalni->gmni_msg_size);
        if (buffer == NULL) {
                CERROR("Failed to gm_dma_malloc tx buffer size [%d]\n", 
                       gmnalni->gmni_msg_size);
                PORTAL_FREE(tx, sizeof(*tx));
                return NULL;
        }

        memset(tx, 0, sizeof(*tx));
        tx->tx_msg = (gmnal_msg_t *)buffer;
        tx->tx_buffer_size = gmnalni->gmni_msg_size;
        tx->tx_gm_size = gm_min_size_for_length(tx->tx_buffer_size);
        tx->tx_gmni = gmnalni;

        CDEBUG(D_NET, "Created tx [%p] with buffer [%p], size [%d]\n", 
               tx, tx->tx_msg, tx->tx_buffer_size);

        return tx;
}

void
gmnal_free_tx (gmnal_tx_t *tx)
{
        gmnal_ni_t *gmnalni = tx->tx_gmni;
        
        CDEBUG(D_NET, "Freeing tx [%p] with buffer [%p], size [%d]\n", 
               tx, tx->tx_msg, tx->tx_buffer_size);
#if 0
        /* We free buffers after we've closed the GM port */
        gm_dma_free(gmnalni->gmni_port, tx->tx_msg);
#endif
        PORTAL_FREE(tx, sizeof(*tx));
}

int
gmnal_alloc_txs(gmnal_ni_t *gmnalni)
{
	int           ntxcred = gm_num_send_tokens(gmnalni->gmni_port);
	int           ntx;
        int           nrxt_tx;
        int           i;
	gmnal_tx_t   *tx;

        CWARN("ntxcred: %d\n", ntxcred);

	ntx = num_txds;
        nrxt_tx = num_txds + 1;

        if (ntx + nrxt_tx > ntxcred) {
                CERROR ("Asked for %d + %d tx credits, but only %d available\n",
                        ntx, nrxt_tx, ntxcred);
                return -ENOMEM;
        }
        
	/* A semaphore is initialised with the number of transmit tokens
	 * available.  To get a stxd, acquire the token semaphore.  this
	 * decrements the available token count (if no tokens you block here,
	 * someone returning a stxd will release the semaphore and wake you)
	 * When token is obtained acquire the spinlock to manipulate the
	 * list */
	sema_init(&gmnalni->gmni_tx_token, ntx);
	spin_lock_init(&gmnalni->gmni_tx_lock);
        LASSERT (gmnalni->gmni_tx == NULL);

	for (i = 0; i <= ntx; i++) {
                tx = gmnal_alloc_tx(gmnalni);
		if (tx == NULL) {
                        CERROR("Failed to create tx %d\n", i);
                        return -ENOMEM;
                }
                
                tx->tx_rxt = 0;
		tx->tx_next = gmnalni->gmni_tx;
		gmnalni->gmni_tx = tx;
	}

	sema_init(&gmnalni->gmni_rxt_tx_token, nrxt_tx);
	spin_lock_init(&gmnalni->gmni_rxt_tx_lock);
        LASSERT (gmnalni->gmni_rxt_tx == NULL);

	for (i = 0; i <= nrxt_tx; i++) {
                tx = gmnal_alloc_tx(gmnalni);
		if (tx == NULL) {
                        CERROR("Failed to create tx %d + %d\n", ntx, i);
                        return -ENOMEM;
                }

                tx->tx_rxt = 1;
		tx->tx_next = gmnalni->gmni_rxt_tx;
		gmnalni->gmni_rxt_tx = tx;
	}

	return 0;
}

void
gmnal_free_txs(gmnal_ni_t *gmnalni)
{
	gmnal_tx_t *tx;

        while ((tx = gmnalni->gmni_tx) != NULL) {
                gmnalni->gmni_tx = tx->tx_next;
                gmnal_free_tx (tx);
	}

        while ((tx = gmnalni->gmni_rxt_tx) != NULL) {
                gmnalni->gmni_rxt_tx = tx->tx_next;
                gmnal_free_tx (tx);
	}
}


/*
 *	Get a tx from the list
 *	This get us a wired and gm_registered small tx buffer.
 *	This implicitly gets us a send token also.
 */
gmnal_tx_t *
gmnal_get_tx(gmnal_ni_t *gmnalni, int block)
{

	gmnal_tx_t	*tx = NULL;
	pid_t		pid = current->pid;


	CDEBUG(D_TRACE, "gmnal_get_tx gmnalni [%p] block[%d] pid [%d]\n", 
	       gmnalni, block, pid);

	if (gmnal_is_rxthread(gmnalni)) {
                CDEBUG(D_NET, "RXTHREAD Attempting to get token\n");
		down(&gmnalni->gmni_rxt_tx_token);
	        spin_lock(&gmnalni->gmni_rxt_tx_lock);
	        tx = gmnalni->gmni_rxt_tx;
		gmnalni->gmni_rxt_tx = tx->tx_next;
	        spin_unlock(&gmnalni->gmni_rxt_tx_lock);
	        CDEBUG(D_NET, "RXTHREAD got [%p], head is [%p]\n", 
		       tx, gmnalni->gmni_rxt_tx);
                tx->tx_rxt = 1;
        } else {
	        if (block) {
                        CDEBUG(D_NET, "Attempting to get token\n");
		        down(&gmnalni->gmni_tx_token);
                        CDEBUG(D_PORTALS, "Got token\n");
	        } else {
		        if (down_trylock(&gmnalni->gmni_tx_token)) {
			        CERROR("can't get token\n");
			        return(NULL);
		        }
	        }
	        spin_lock(&gmnalni->gmni_tx_lock);
	        tx = gmnalni->gmni_tx;
		gmnalni->gmni_tx = tx->tx_next;
	        spin_unlock(&gmnalni->gmni_tx_lock);
	        CDEBUG(D_NET, "got [%p], head is [%p]\n", tx,
		       gmnalni->gmni_tx);
        }       /* general tx get */

	return tx;
}

/*
 *	Return a tx to the list
 */
void
gmnal_return_tx(gmnal_ni_t *gmnalni, gmnal_tx_t *tx)
{
	CDEBUG(D_TRACE, "gmnalni [%p], tx[%p] rxt[%d]\n", gmnalni,
	       tx, tx->tx_rxt);

        /*
         *      this transmit descriptor is 
         *      for the rxthread
         */
        if (tx->tx_rxt) {
	        spin_lock(&gmnalni->gmni_rxt_tx_lock);
	        tx->tx_next = gmnalni->gmni_rxt_tx;
	        gmnalni->gmni_rxt_tx = tx;
	        spin_unlock(&gmnalni->gmni_rxt_tx_lock);
	        up(&gmnalni->gmni_rxt_tx_token);
                CDEBUG(D_NET, "Returned tx to rxthread list\n");
        } else {
	        spin_lock(&gmnalni->gmni_tx_lock);
	        tx->tx_next = gmnalni->gmni_tx;
	        gmnalni->gmni_tx = tx;
	        spin_unlock(&gmnalni->gmni_tx_lock);
	        up(&gmnalni->gmni_tx_token);
                CDEBUG(D_NET, "Returned tx to general list\n");
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
gmnal_alloc_rxs (gmnal_ni_t *gmnalni)
{
        int          nrxcred = gm_num_receive_tokens(gmnalni->gmni_port);
        int          nrx;
        int          i;
	gmnal_rx_t  *rxd;
	void	    *rxbuffer;

        CWARN("nrxcred: %d\n", nrxcred);

	nrx = num_txds*2 + 2;
        if (nrx > nrxcred) {
                CERROR("Can't allocate %d rx credits: (%d available)\n",
                       nrx, nrxcred);
                return -ENOMEM;
        }

	CDEBUG(D_NET, "Allocated [%d] receive tokens to small messages\n", nrx);

	gmnalni->gmni_rx_hash = gm_create_hash(gm_hash_compare_ptrs, 
                                               gm_hash_hash_ptr, 0, 0, nrx, 0);
	if (gmnalni->gmni_rx_hash == NULL) {
                CERROR("Failed to create hash table\n");
                return -ENOMEM;
	}

        LASSERT (gmnalni->gmni_rx == NULL);

	for (i=0; i <= nrx; i++) {

		PORTAL_ALLOC(rxd, sizeof(*rxd));
		if (rxd == NULL) {
			CERROR("Failed to malloc rxd [%d]\n", i);
			return -ENOMEM;
		}

		rxbuffer = gm_dma_malloc(gmnalni->gmni_port, 
					 gmnalni->gmni_msg_size);
		if (rxbuffer == NULL) {
			CERROR("Failed to gm_dma_malloc rxbuffer [%d], "
			       "size [%d]\n",i ,gmnalni->gmni_msg_size);
			PORTAL_FREE(rxd, sizeof(*rxd));
			return -ENOMEM;
		}

		rxd->rx_msg = (gmnal_msg_t *)rxbuffer;
		rxd->rx_size = gmnalni->gmni_msg_size;
		rxd->rx_gmsize = gm_min_size_for_length(rxd->rx_size);

		rxd->rx_next = gmnalni->gmni_rx;
		gmnalni->gmni_rx = rxd;

		if (gm_hash_insert(gmnalni->gmni_rx_hash,
				   (void*)rxbuffer, (void*)rxd)) {
			CERROR("failed to create hash entry rxd[%p] "
			       "for rxbuffer[%p]\n", rxd, rxbuffer);
			return -ENOMEM;
		}

		CDEBUG(D_NET, "Registered rxd [%p] with buffer [%p], "
		       "size [%d]\n", rxd, rxd->rx_msg, rxd->rx_size);
	}

	return 0;
}

void
gmnal_free_rxs(gmnal_ni_t *gmnalni)
{
	gmnal_rx_t *rx;

	CDEBUG(D_TRACE, "gmnal_free_small rx\n");

	while ((rx = gmnalni->gmni_rx) != NULL) {
                gmnalni->gmni_rx = rx->rx_next;

		CDEBUG(D_NET, "Freeing rxd [%p] buffer [%p], size [%d]\n",
		       rx, rx->rx_msg, rx->rx_size);
#if 0
                /* We free buffers after we've shutdown the GM port */
		gm_dma_free(gmnalni->gmni_port, _rxd->rx_msg);
#endif
		PORTAL_FREE(rx, sizeof(*rx));
	}

#if 0
        /* see above */
        if (gmnalni->gmni_rx_hash != NULL)
                gm_destroy_hash(gmnalni->gmni_rx_hash);
#endif
}

void
gmnal_stop_rxthread(gmnal_ni_t *gmnalni)
{
	int 	count = 2;
        int     i;
	
	gmnalni->gmni_rxthread_stop_flag = GMNAL_THREAD_STOP;

        for (i = 0; i < num_rx_threads; i++)
                up(&gmnalni->gmni_rxq_wait);

	while (gmnalni->gmni_rxthread_flag != GMNAL_THREAD_RESET) {
		CDEBUG(D_NET, "gmnal_stop_rxthread sleeping\n");
                gmnal_yield(1);

                count++;
                if ((count & (count - 1)) == 0)
                        CWARN("Waiting for rxthreads to stop\n");
	}
}

void
gmnal_stop_ctthread(gmnal_ni_t *gmnalni)
{
        int count = 2;

	gmnalni->gmni_ctthread_flag = GMNAL_THREAD_STOP;

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_set_alarm(gmnalni->gmni_port, &gmnalni->gmni_ctthread_alarm, 10, 
		     NULL, NULL);
	spin_unlock(&gmnalni->gmni_gm_lock);

	while (gmnalni->gmni_ctthread_flag == GMNAL_THREAD_STOP) {
		CDEBUG(D_NET, "gmnal_stop_ctthread sleeping\n");
                gmnal_yield(1);
                count++;
                if ((count & (count - 1)) == 0)
                        CWARN("Waiting for ctthread to stop\n");
	}
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
        int     flag;
        
        INIT_LIST_HEAD(&gmnalni->gmni_rxq);
	spin_lock_init(&gmnalni->gmni_rxq_lock);
	sema_init(&gmnalni->gmni_rxq_wait, 0);

	/*
 	 *	the alarm is used to wake the caretaker thread from 
	 *	gm_unknown call (sleeping) to exit it.
	 */
	CDEBUG(D_NET, "Initializing caretaker thread alarm and flag\n");
	gm_initialize_alarm(&gmnalni->gmni_ctthread_alarm);

	CDEBUG(D_NET, "Starting caretaker thread\n");
	gmnalni->gmni_ctthread_flag = GMNAL_THREAD_RESET;
	gmnalni->gmni_ctthread_pid = 
	         kernel_thread(gmnal_ct_thread, (void*)gmnalni, 0);
	if (gmnalni->gmni_ctthread_pid <= 0) {
		CERROR("Caretaker thread failed to start\n");
		return -ENOMEM;
	}

	while (gmnalni->gmni_ctthread_flag != GMNAL_THREAD_RESET) {
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

	spin_lock_init(&gmnalni->gmni_rxthread_flag_lock);
	for (threads=0; threads<NRXTHREADS; threads++)
		gmnalni->gmni_rxthread_pid[threads] = -1;

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
                flag = gmnalni->gmni_rxthread_flag;
		spin_unlock(&gmnalni->gmni_rxthread_flag_lock);
                
		if (flag == GMNAL_RXTHREADS_STARTED)
                        break;

		gmnal_yield(1);
	}

	CDEBUG(D_NET, "receive threads seem to have started\n");

	return 0;
}

char * 
gmnal_gmstatus2str(gm_status_t status)
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
gmnal_rxevent2str(gm_recv_event_t *ev)
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
        /* _GM_PUT_NOTIFICATION_EVENT */
        /* GM_FREE_SEND_TOKEN_EVENT */
        /* GM_FREE_HIGH_SEND_TOKEN_EVENT */
        }
}


void
gmnal_yield(int delay)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(delay);
}

int
gmnal_enqueue_rx(gmnal_ni_t *gmnalni, gm_recv_t *recv)
{
        void       *ptr = gm_ntohp(recv->buffer);
        gmnal_rx_t *rx = gm_hash_find(gmnalni->gmni_rx_hash, ptr);

        /* No locking; hash is read-only */

	LASSERT (rx != NULL);
        LASSERT (rx->rx_msg == (gmnal_msg_t *)ptr);

        rx->rx_recv_nob = gm_ntohl(recv->length);
        rx->rx_recv_gmid = gm_ntoh_u16(recv->sender_node_id);
        rx->rx_recv_port = gm_ntoh_u8(recv->sender_port_id);
        rx->rx_recv_type = gm_ntoh_u8(recv->type);
        
	spin_lock(&gmnalni->gmni_rxq_lock);
        list_add_tail (&rx->rx_list, &gmnalni->gmni_rxq);
	spin_unlock(&gmnalni->gmni_rxq_lock);

	up(&gmnalni->gmni_rxq_wait);
	return 0;
}

gmnal_rx_t *
gmnal_dequeue_rx(gmnal_ni_t *gmnalni)
{
	gmnal_rx_t	*rx;

	CDEBUG(D_NET, "Getting entry to list\n");

        for (;;) {
		while(down_interruptible(&gmnalni->gmni_rxq_wait) != 0)
                        /* do nothing */;

		if (gmnalni->gmni_rxthread_stop_flag == GMNAL_THREAD_STOP)
			return NULL;

		spin_lock(&gmnalni->gmni_rxq_lock);

                if (list_empty(&gmnalni->gmni_rxq)) {
                        rx = NULL;
                } else {
                        rx = list_entry(gmnalni->gmni_rxq.next,
                                        gmnal_rx_t, rx_list);
                        list_del(&rx->rx_list);
                }

		spin_unlock(&gmnalni->gmni_rxq_lock);

                if (rx != NULL)
                        return rx;
                
                CWARN("woken but no work\n");
	}
}


