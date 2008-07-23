/*
 * -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include "gmlnd.h"

void
gmnal_free_netbuf_pages (gmnal_netbuf_t *nb, int npages) 
{
        int     i;
        
        for (i = 0; i < npages; i++)
                __free_page(nb->nb_kiov[i].kiov_page);
}

int
gmnal_alloc_netbuf_pages (gmnal_ni_t *gmni, gmnal_netbuf_t *nb, int npages)
{
        int          i;
        gm_status_t  gmrc;

        LASSERT (npages > 0);

        for (i = 0; i < npages; i++) {
                nb->nb_kiov[i].kiov_page = alloc_page(GFP_KERNEL);
                nb->nb_kiov[i].kiov_offset = 0;
                nb->nb_kiov[i].kiov_len = PAGE_SIZE;

                if (nb->nb_kiov[i].kiov_page == NULL) {
                        CERROR("Can't allocate page\n");
                        gmnal_free_netbuf_pages(nb, i);
                        return -ENOMEM;
                }

                CDEBUG(D_NET,"[%3d] page %p, phys "LPX64", @ "LPX64"\n",
                       i, nb->nb_kiov[i].kiov_page, 
                       lnet_page2phys(nb->nb_kiov[i].kiov_page),
                       gmni->gmni_netaddr_base);

                gmrc = gm_register_memory_ex_phys(
                        gmni->gmni_port,
                        lnet_page2phys(nb->nb_kiov[i].kiov_page),
                        PAGE_SIZE,
                        gmni->gmni_netaddr_base);
                CDEBUG(D_NET,"[%3d] page %p: %d\n", 
                       i, nb->nb_kiov[i].kiov_page, gmrc);

                if (gmrc != GM_SUCCESS) {
                        CERROR("Can't map page: %d(%s)\n", gmrc,
                               gmnal_gmstatus2str(gmrc));
                        gmnal_free_netbuf_pages(nb, i+1);
                        return -ENOMEM;
                }

                if (i == 0) 
                        nb->nb_netaddr = gmni->gmni_netaddr_base;

                gmni->gmni_netaddr_base += PAGE_SIZE;
        }

        return 0;
}

void
gmnal_free_ltxbuf (gmnal_ni_t *gmni, gmnal_txbuf_t *txb)
{
        int            npages = gmni->gmni_large_pages;

        LASSERT (gmni->gmni_port == NULL);
        /* No unmapping; the port has been closed */

        gmnal_free_netbuf_pages(&txb->txb_buf, gmni->gmni_large_pages);
        LIBCFS_FREE(txb, offsetof(gmnal_txbuf_t, txb_buf.nb_kiov[npages]));
}

int
gmnal_alloc_ltxbuf (gmnal_ni_t *gmni)
{
        int            npages = gmni->gmni_large_pages;
        int            sz = offsetof(gmnal_txbuf_t, txb_buf.nb_kiov[npages]);
        gmnal_txbuf_t *txb;
        int            rc;

        LIBCFS_ALLOC(txb, sz);
        if (txb == NULL) {
                CERROR("Can't allocate large txbuffer\n");
                return -ENOMEM;
        }

        rc = gmnal_alloc_netbuf_pages(gmni, &txb->txb_buf, npages);
        if (rc != 0) {
                LIBCFS_FREE(txb, sz);
                return rc;
        }

        list_add_tail(&txb->txb_list, &gmni->gmni_idle_ltxbs);

        txb->txb_next = gmni->gmni_ltxbs;
        gmni->gmni_ltxbs = txb;

        return 0;
}

void
gmnal_free_tx (gmnal_tx_t *tx)
{
        LASSERT (tx->tx_gmni->gmni_port == NULL);

        gmnal_free_netbuf_pages(&tx->tx_buf, 1);
        LIBCFS_FREE(tx, sizeof(*tx));
}

int
gmnal_alloc_tx (gmnal_ni_t *gmni) 
{
        gmnal_tx_t  *tx;
        int          rc;
        
        LIBCFS_ALLOC(tx, sizeof(*tx));
        if (tx == NULL) {
                CERROR("Failed to allocate tx\n");
                return -ENOMEM;
        }
        
        memset(tx, 0, sizeof(*tx));

        rc = gmnal_alloc_netbuf_pages(gmni, &tx->tx_buf, 1);
        if (rc != 0) {
                LIBCFS_FREE(tx, sizeof(*tx));
                return -ENOMEM;
        }

        tx->tx_gmni = gmni;
        
        list_add_tail(&tx->tx_list, &gmni->gmni_idle_txs);

        tx->tx_next = gmni->gmni_txs;
        gmni->gmni_txs = tx;
                
        return 0;
}

void
gmnal_free_rx(gmnal_ni_t *gmni, gmnal_rx_t *rx)
{
        int   npages = rx->rx_islarge ? gmni->gmni_large_pages : 1;
        
        LASSERT (gmni->gmni_port == NULL);

        gmnal_free_netbuf_pages(&rx->rx_buf, npages);
        LIBCFS_FREE(rx, offsetof(gmnal_rx_t, rx_buf.nb_kiov[npages]));
}

int
gmnal_alloc_rx (gmnal_ni_t *gmni, int islarge)
{
        int         npages = islarge ? gmni->gmni_large_pages : 1;
        int         sz = offsetof(gmnal_rx_t, rx_buf.nb_kiov[npages]);
        int         rc;
        gmnal_rx_t *rx;
        gm_status_t gmrc;
        
        LIBCFS_ALLOC(rx, sz);
        if (rx == NULL) {
                CERROR("Failed to allocate rx\n");
                return -ENOMEM;
        }
        
        memset(rx, 0, sizeof(*rx));

        rc = gmnal_alloc_netbuf_pages(gmni, &rx->rx_buf, npages);
        if (rc != 0) {
                LIBCFS_FREE(rx, sz);
                return rc;
        }
        
        rx->rx_islarge = islarge;
        rx->rx_next = gmni->gmni_rxs;
        gmni->gmni_rxs = rx;

        gmrc = gm_hash_insert(gmni->gmni_rx_hash, 
                              GMNAL_NETBUF_LOCAL_NETADDR(&rx->rx_buf), rx);
        if (gmrc != GM_SUCCESS) {
                CERROR("Couldn't add rx to hash table: %d\n", gmrc);
                return -ENOMEM;
        }
        
        return 0;
}

void
gmnal_free_ltxbufs (gmnal_ni_t *gmni)
{
        gmnal_txbuf_t *txb;
        
        while ((txb = gmni->gmni_ltxbs) != NULL) {
                gmni->gmni_ltxbs = txb->txb_next;
                gmnal_free_ltxbuf(gmni, txb);
        }
}

int
gmnal_alloc_ltxbufs (gmnal_ni_t *gmni)
{
        int     nlarge_tx_bufs = *gmnal_tunables.gm_nlarge_tx_bufs;
        int     i;
        int     rc;

        for (i = 0; i < nlarge_tx_bufs; i++) {
                rc = gmnal_alloc_ltxbuf(gmni);

                if (rc != 0)
                        return rc;
        }

        return 0;
}

void
gmnal_free_txs(gmnal_ni_t *gmni)
{
	gmnal_tx_t *tx;

        while ((tx = gmni->gmni_txs) != NULL) {
                gmni->gmni_txs = tx->tx_next;
                gmnal_free_tx (tx);
	}
}

int
gmnal_alloc_txs(gmnal_ni_t *gmni)
{
        int           ntxcred = gm_num_send_tokens(gmni->gmni_port);
        int           ntx = *gmnal_tunables.gm_ntx;
        int           i;
        int           rc;

        CDEBUG(D_NET, "ntxcred: %d\n", ntxcred);
        gmni->gmni_tx_credits = ntxcred;

        for (i = 0; i < ntx; i++) {
                rc = gmnal_alloc_tx(gmni);
                if (rc != 0)
                        return rc;
        }

        return 0;
}

void
gmnal_free_rxs(gmnal_ni_t *gmni)
{
	gmnal_rx_t *rx;

	while ((rx = gmni->gmni_rxs) != NULL) {
                gmni->gmni_rxs = rx->rx_next;

                gmnal_free_rx(gmni, rx);
        }

        LASSERT (gmni->gmni_port == NULL);
#if 0
        /* GM releases all resources allocated to a port when it closes */
        if (gmni->gmni_rx_hash != NULL)
                gm_destroy_hash(gmni->gmni_rx_hash);
#endif
}

int
gmnal_alloc_rxs (gmnal_ni_t *gmni)
{
        int          nrxcred = gm_num_receive_tokens(gmni->gmni_port);
        int          nrx_small = *gmnal_tunables.gm_nrx_small;
        int          nrx_large = *gmnal_tunables.gm_nrx_large;
        int          nrx = nrx_large + nrx_small;
        int          rc;
        int          i;

        CDEBUG(D_NET, "nrxcred: %d(%dL+%dS)\n", nrxcred, nrx_large, nrx_small);

        if (nrx > nrxcred) {
                int nlarge = (nrx_large * nrxcred)/nrx;
                int nsmall = nrxcred - nlarge;
                
                CWARN("Only %d rx credits: "
                      "reducing large %d->%d, small %d->%d\n", nrxcred,
                      nrx_large, nlarge, nrx_small, nsmall);
                
                *gmnal_tunables.gm_nrx_large = nrx_large = nlarge;
                *gmnal_tunables.gm_nrx_small = nrx_small = nsmall;
                nrx = nlarge + nsmall;
        }
        
	gmni->gmni_rx_hash = gm_create_hash(gm_hash_compare_ptrs, 
                                            gm_hash_hash_ptr, 0, 0, nrx, 0);
	if (gmni->gmni_rx_hash == NULL) {
                CERROR("Failed to create hash table\n");
                return -ENOMEM;
	}

        for (i = 0; i < nrx; i++ ) {
                rc = gmnal_alloc_rx(gmni, i < nrx_large);
                if (rc != 0)
                        return rc;
        }

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
