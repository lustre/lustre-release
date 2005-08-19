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

void
gmnal_pack_msg(gmnal_ni_t *gmnalni, gmnal_tx_t *tx,
               ptl_nid_t dstnid, int type)
{
        gmnal_msg_t *msg = tx->tx_msg;

        /* CAVEAT EMPTOR! this only sets the common message fields. */
        msg->gmm_magic    = GMNAL_MSG_MAGIC;
        msg->gmm_version  = GMNAL_MSG_VERSION;
        msg->gmm_type     = type;
        msg->gmm_srcnid   = gmnalni->gmni_libnal->libnal_ni.ni_pid.nid;
        msg->gmm_dstnid   = dstnid;
}

int
gmnal_unpack_msg(gmnal_ni_t *gmnalni, gmnal_rx_t *rx)
{
        gmnal_msg_t *msg = rx->rx_msg;
        const int    hdr_size = offsetof(gmnal_msg_t, gmm_u);
        int          flip;

        /* 6 bytes are enough to have received magic + version */
        if (rx->rx_recv_nob < 6) {
                CERROR("Short message from gmid %u: %d\n", 
                       rx->rx_recv_gmid, rx->rx_recv_nob);
                return -EPROTO;
        }

        if (msg->gmm_magic == GMNAL_MSG_MAGIC) {
                flip = 0;
        } else if (msg->gmm_magic == __swab32(GMNAL_MSG_MAGIC)) {
                flip = 1;
        } else {
                CERROR("Bad magic from gmid %u: %08x\n", 
                       rx->rx_recv_gmid, msg->gmm_magic);
                return -EPROTO;
        }

        if (msg->gmm_version != 
            (flip ? __swab16(GMNAL_MSG_VERSION) : GMNAL_MSG_VERSION)) {
                CERROR("Bad version from gmid %u: %d\n", 
                       rx->rx_recv_gmid, msg->gmm_version);
                return -EPROTO;
        }

        if (rx->rx_recv_nob < hdr_size) {
                CERROR("Short message from %u: %d\n",
                       rx->rx_recv_gmid, rx->rx_recv_nob);
                return -EPROTO;
        }

        if (flip) {
                /* leave magic unflipped as a clue to peer endianness */
                __swab16s(&msg->gmm_version);
                __swab16s(&msg->gmm_type);
                __swab64s(&msg->gmm_srcnid);
                __swab64s(&msg->gmm_dstnid);
        }
        
        if (msg->gmm_srcnid == PTL_NID_ANY) {
                CERROR("Bad src nid from %u: "LPX64"\n", 
                       rx->rx_recv_gmid, msg->gmm_srcnid);
                return -EPROTO;
        }

        if (msg->gmm_dstnid != gmnalni->gmni_libnal->libnal_ni.ni_pid.nid) {
                CERROR("Bad dst nid from %u: "LPX64"\n",
                       rx->rx_recv_gmid, msg->gmm_dstnid);
                return -EPROTO;
        }
        
        switch (msg->gmm_type) {
        default:
                CERROR("Unknown message type from %u: %x\n", 
                       rx->rx_recv_gmid, msg->gmm_type);
                return -EPROTO;
                
        case GMNAL_MSG_IMMEDIATE:
                if (rx->rx_recv_nob < offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[0])) {
                        CERROR("Short IMMEDIATE from %u: %d("LPSZ")\n", 
                               rx->rx_recv_gmid, rx->rx_recv_nob, 
                               offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[0]));
                        return -EPROTO;
                }
                break;
        }
        return 0;
}


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
	gmnal_ni_t		*gmnalni = arg;
	gm_recv_event_t		*rxevent = NULL;
	gm_recv_t		*recv = NULL;

	sprintf(current->comm, "gmnal_ct");
	kportal_daemonize("gmnalctd");

	gmnalni->gmni_ctthread_flag = GMNAL_CTTHREAD_STARTED;

	while(gmnalni->gmni_ctthread_flag == GMNAL_CTTHREAD_STARTED) {

                spin_lock(&gmnalni->gmni_gm_lock);
		rxevent = gm_blocking_receive_no_spin(gmnalni->gmni_port);
                spin_unlock(&gmnalni->gmni_gm_lock);

		if (gmnalni->gmni_ctthread_flag == GMNAL_THREAD_STOP) {
			CDEBUG(D_NET, "time to exit\n");
			break;
		}

		CDEBUG(D_NET, "got [%s]\n", gmnal_rxevent2str(rxevent));

		if (GM_RECV_EVENT_TYPE(rxevent) == GM_RECV_EVENT) {
                        recv = (gm_recv_t*)&rxevent->recv;
                        gmnal_enqueue_rx(gmnalni, recv);
                } else {
                        gm_unknown(gmnalni->gmni_port, rxevent);
		}
	}

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
	gmnal_ni_t    *gmnalni = arg;
        char           name[16];
	gmnal_rx_t    *rx;
	int	       rank;

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
	spin_unlock(&gmnalni->gmni_rxthread_flag_lock);

	while(gmnalni->gmni_rxthread_stop_flag != GMNAL_THREAD_STOP) {
		CDEBUG(D_NET, "RXTHREAD:: Receive thread waiting\n");

		rx = gmnal_dequeue_rx(gmnalni);
		if (rx == NULL) {
			CDEBUG(D_NET, "Receive thread time to exit\n");
			break;
		}
                
                /* We're connectionless: simply ignore packets on error */
                
                if (gmnal_unpack_msg(gmnalni, rx) == 0) {
                        
                        LASSERT (rx->rx_msg->gmm_type == GMNAL_MSG_IMMEDIATE);
                        (void)lib_parse(gmnalni->gmni_libnal, 
                                        &rx->rx_msg->gmm_u.immediate.gmim_hdr,
                                        rx);
                }

                gmnal_post_rx(gmnalni, rx);
	}

	spin_lock(&gmnalni->gmni_rxthread_flag_lock);
	gmnalni->gmni_rxthread_flag /= 2;
	spin_unlock(&gmnalni->gmni_rxthread_flag_lock);

	CDEBUG(D_NET, "thread gmnalni [%p] is exiting\n", gmnalni);
	return 0;
}

void
gmnal_post_rx(gmnal_ni_t *gmnalni, gmnal_rx_t *rx)
{
	CDEBUG(D_NET, "requeueing rx[%p] gmnalni[%p]\n", rx, gmnalni);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_provide_receive_buffer_with_tag(gmnalni->gmni_port, rx->rx_msg,
                                           rx->rx_gmsize, GM_LOW_PRIORITY, 0 );
	spin_unlock(&gmnalni->gmni_gm_lock);
}

void 
gmnal_resume_sending_callback(struct gm_port *gm_port, void *context,
                              gm_status_t status)
{
	gmnal_tx_t	*tx = (gmnal_tx_t*)context;
	gmnal_ni_t	*gmnalni = tx->tx_gmni;
	lib_msg_t	*libmsg = tx->tx_libmsg;

        CWARN("status for tx [%p] is [%d][%s]\n", 
              tx, status, gmnal_gmstatus2str(status));

        gmnal_return_tx(gmnalni, tx);
        lib_finalize(gmnalni->gmni_libnal, NULL, libmsg, PTL_FAIL);
}

void 
gmnal_drop_sends_callback(struct gm_port *gm_port, void *context, 
                          gm_status_t status)
{
	gmnal_tx_t	*tx = (gmnal_tx_t*)context;
	gmnal_ni_t	*gmnalni = tx->tx_gmni;

        CERROR("status for tx [%p] is [%d][%s]\n", 
               tx, status, gmnal_gmstatus2str(status));

        gm_resume_sending(gmnalni->gmni_port, tx->tx_gm_priority,
                          tx->tx_gmlid, gm_port_id,
                          gmnal_resume_sending_callback, tx);
}

void 
gmnal_tx_callback(gm_port_t *gm_port, void *context, gm_status_t status)
{
	gmnal_tx_t	*tx = (gmnal_tx_t*)context;
	gmnal_ni_t	*gmnalni = tx->tx_gmni;
	lib_nal_t	*libnal = gmnalni->gmni_libnal;
	lib_msg_t	*libmsg = tx->tx_libmsg;
        ptl_err_t        rc;

	if (!tx) {
		CERROR("send completion event for unknown tx\n");
		return;
	}

	switch(status) {
        case(GM_SUCCESS):
                rc = PTL_OK;
                break;

        case(GM_SEND_DROPPED):
                rc = PTL_FAIL;
                break;
                        
        default:
                CERROR("Error %d(%s), nid "LPD64"\n",
                       status, gmnal_gmstatus2str(status), tx->tx_nid);

                spin_lock(&gmnalni->gmni_gm_lock);
                gm_drop_sends(gmnalni->gmni_port, tx->tx_gm_priority, 
                              tx->tx_gmlid, gm_port_id, 
                              gmnal_drop_sends_callback, tx);
                spin_unlock(&gmnalni->gmni_gm_lock);
		return;
	}

	gmnal_return_tx(gmnalni, tx);
	lib_finalize(libnal, NULL, libmsg, rc);
	return;
}

ptl_err_t
gmnal_post_tx (gmnal_ni_t *gmnalni, gmnal_tx_t *tx, 
               lib_msg_t *libmsg, ptl_nid_t nid, int nob)
{
        gm_status_t  gm_status;

	CDEBUG(D_NET, "send %d bytes to "LPU64"\n", nob, nid);

        LASSERT ((nid >> 32) == 0);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_status = gm_global_id_to_node_id(gmnalni->gmni_port, (__u32)nid, 
                                            &tx->tx_gmlid);
	spin_unlock(&gmnalni->gmni_gm_lock);

	if (gm_status != GM_SUCCESS) {
		CERROR("Failed to obtain local id\n");
                gmnal_return_tx(gmnalni, tx);
		return PTL_FAIL;
	}

	CDEBUG(D_NET, "Local Node_id is [%u][%x]\n", 
               tx->tx_gmlid, tx->tx_gmlid);

        tx->tx_nid = nid;
	tx->tx_libmsg = libmsg;
	tx->tx_gm_priority = GM_LOW_PRIORITY;
	tx->tx_msg_size = nob;

	CDEBUG(D_NET, "Calling gm_send_to_peer port [%p] buffer [%p] "
	       "gmsize [%lu] msize [%d] nid ["LPU64"] local_gmid[%d] "
	       "tx [%p]\n", gmnalni->gmni_port, tx->tx_msg, 
               tx->tx_gm_size, tx->tx_msg_size, 
               tx->tx_nid, tx->tx_gmlid, tx);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_send_to_peer_with_callback(gmnalni->gmni_port, tx->tx_msg,
				      tx->tx_gm_size, tx->tx_msg_size,
                                      tx->tx_gm_priority, tx->tx_gmlid,
				      gmnal_tx_callback, (void*)tx);
	spin_unlock(&gmnalni->gmni_gm_lock);

	return PTL_OK;
}
