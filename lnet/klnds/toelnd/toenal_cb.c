/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *   Author: Kedar Sovani <kedar@calsoftinc.com>
 *   Author: Amey Inamdar <amey@calsoftinc.com>
 *   
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <linux/poll.h>
#include "toenal.h"

atomic_t   ktoenal_packets_received;
long       ktoenal_packets_launched;
long       ktoenal_packets_transmitted;

/*
 *  LIB functions follow
 *
 */
int
ktoenal_read(nal_cb_t *nal, void *private, void *dst_addr,
              user_ptr src_addr, size_t len)
{
        CDEBUG(D_NET, LPX64": reading %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr);

        memcpy( dst_addr, src_addr, len );
        return 0;
}

int
ktoenal_write(nal_cb_t *nal, void *private, user_ptr dst_addr,
               void *src_addr, size_t len)
{
        CDEBUG(D_NET, LPX64": writing %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr);

        memcpy( dst_addr, src_addr, len );
        return 0;
}

int 
ktoenal_callback (nal_cb_t * nal, void *private, lib_eq_t *eq,
			 ptl_event_t *ev)
{
        CDEBUG(D_NET, LPX64": callback eq %p ev %p\n",
               nal->ni.nid, eq, ev);

        if (eq->event_callback != NULL) 
                eq->event_callback(ev);

        return 0;
}

void *
ktoenal_malloc(nal_cb_t *nal, size_t len)
{
        void *buf;

        PORTAL_ALLOC(buf, len);

        if (buf != NULL)
                memset(buf, 0, len);

        return (buf);
}

void
ktoenal_free(nal_cb_t *nal, void *buf, size_t len)
{
        PORTAL_FREE(buf, len);
}

void
ktoenal_printf(nal_cb_t *nal, const char *fmt, ...)
{
	va_list ap;
	char msg[256];

	va_start (ap, fmt);
	vsnprintf (msg, sizeof (msg), fmt, ap); /* sprint safely */
	va_end (ap);

	msg[sizeof (msg) - 1] = 0;              /* ensure terminated */

        CDEBUG (D_NET, "%s", msg);
}

void
ktoenal_cli(nal_cb_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *data = nal->nal_data;

        spin_lock(&data->ksnd_nal_cb_lock);
}

void
ktoenal_sti(nal_cb_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *data;
        data = nal->nal_data;

        spin_unlock(&data->ksnd_nal_cb_lock);
}

int
ktoenal_dist(nal_cb_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        /* I would guess that if ktoenal_get_conn(nid) == NULL,
           and we're not routing, then 'nid' is very distant :) */
        if ( nal->ni.nid == nid ) {
                *dist = 0;
        } else {
                *dist = 1;
        }

        return 0;
}

ksock_ltx_t *
ktoenal_get_ltx (int may_block)
{
        long	     flags;
        ksock_ltx_t *ltx = NULL;
        
        for (;;)
        {
                spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, flags);
        
                if (!list_empty (&ktoenal_data.ksnd_idle_ltx_list))
                {
                        ltx = list_entry (ktoenal_data.ksnd_idle_ltx_list.next, ksock_ltx_t, ltx_tx.tx_list);
                        list_del (&ltx->ltx_tx.tx_list);
                        break;
                }

                if (!may_block)
                {
                        if (!list_empty (&ktoenal_data.ksnd_idle_nblk_ltx_list))
                        {
                                ltx = list_entry (ktoenal_data.ksnd_idle_nblk_ltx_list.next, 
                                                  ksock_ltx_t, ltx_tx.tx_list);
                                list_del (&ltx->ltx_tx.tx_list);
                        }
                        break;
                }
                
                spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);
                
                wait_event (ktoenal_data.ksnd_idle_ltx_waitq,
                            !list_empty (&ktoenal_data.ksnd_idle_ltx_list));
        }

        spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);

        return (ltx);
}

int
ktoenal_sendmsg (struct file *sock, struct iovec *iov, int niov, int nob, int flags)
{
        /* NB This procedure "consumes" iov (actually we do, tcp_sendmsg doesn't)
         */
        mm_segment_t oldmm;
        int           rc;

        LASSERT (niov > 0);
        LASSERT (nob > 0);
        
        oldmm = get_fs();
        set_fs (KERNEL_DS);

#ifdef PORTAL_DEBUG
        {
                int total_nob;
                int i;
                
                for (i = total_nob = 0; i < niov; i++)
                        total_nob += iov[i].iov_len;
                
                LASSERT (nob == total_nob);
        }
#endif        
        LASSERT (!in_interrupt());
       
        rc = sock->f_op->writev(sock, iov, niov, NULL);

        set_fs (oldmm);

        if (rc > 0)                             /* sent something? */
        {
                nob = rc;                       /* consume iov */
                for (;;)
                {
                        LASSERT (niov > 0);
                        
                        if (iov->iov_len >= nob)
                        {
                                iov->iov_len -= nob;
                                iov->iov_base = (void *)(((unsigned long)iov->iov_base) + nob);
                                break;
                        }
                        nob -= iov->iov_len;
                        iov->iov_len = 0;
                        iov++;
                        niov--;
                }
        }

        return (rc);
}

int
ktoenal_recvmsg(struct file *sock, struct iovec *iov, int niov, int toread)
{
        /* NB This procedure "consumes" iov (actually tcp_recvmsg does)
         */
        mm_segment_t oldmm;
        int ret, i, len = 0, origlen = 0;
        
        PROF_START(our_recvmsg);
        for(i = 0; i < niov; i++) {
                len += iov[i].iov_len;
                if(len >= toread)
                        break;
        }

        if(len >= toread) {
                origlen = iov[i].iov_len;
                iov[i].iov_len -= (len - toread);
        }
        else {  /* i == niov */
                i = niov - 1;
        }

        oldmm = get_fs();
        set_fs(KERNEL_DS);

        ret = sock->f_op->readv(sock, iov, i + 1, NULL);
        
        set_fs(oldmm);

        if(origlen)
                iov[i].iov_len = origlen;

        PROF_FINISH(our_recvmsg);
        return ret;
}

void
ktoenal_process_transmit (ksock_conn_t *conn, long *irq_flags)
{
        ksock_tx_t *tx = list_entry (conn->ksnc_tx_queue.next, ksock_tx_t, tx_list);
        int         rc;
        
        LASSERT (conn->ksnc_tx_scheduled);
        LASSERT (conn->ksnc_tx_ready);
        LASSERT (!list_empty (&conn->ksnc_tx_queue));

        /* assume transmit will complete now, so dequeue while I've got the lock */
        list_del (&tx->tx_list);

        spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, *irq_flags);

        LASSERT (tx->tx_nob > 0);

        conn->ksnc_tx_ready = 0;                /* write_space may race with me and set ready */
        mb();                                   /* => clear BEFORE trying to write */

        rc = ktoenal_sendmsg (conn->ksnc_file,
                               tx->tx_iov, tx->tx_niov, tx->tx_nob,
                               list_empty (&conn->ksnc_tx_queue) ? 
                               MSG_DONTWAIT : (MSG_DONTWAIT | MSG_MORE));

        CDEBUG (D_NET, "send(%d) %d\n", tx->tx_nob, rc);

        if (rc < 0)                             /* error */
        {
                if (rc == -EAGAIN)              /* socket full => */
                        rc = 0;                 /* nothing sent */
                else
                {
#warning FIXME: handle socket errors properly
                        CERROR ("Error socknal send(%d) %p: %d\n", tx->tx_nob, conn, rc);
                        rc = tx->tx_nob;        /* kid on for now whole packet went */
                }
        }

        if (rc == tx->tx_nob)                   /* everything went */
        {
                conn->ksnc_tx_ready = 1;        /* assume more can go (ASAP) */
                ktoenal_put_conn (conn);       /* release packet's ref */

                if (tx->tx_isfwd)               /* was a forwarded packet? */
                {
                        kpr_fwd_done (&ktoenal_data.ksnd_router,
                                      KSOCK_TX_2_KPR_FWD_DESC (tx), 0);

                        spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, *irq_flags);
                }
                else                            /* local send */
                {
                        ksock_ltx_t *ltx = KSOCK_TX_2_KSOCK_LTX (tx);

                        lib_finalize (&ktoenal_lib, ltx->ltx_private, ltx->ltx_cookie);

                        spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, *irq_flags);
                        
                        list_add (&ltx->ltx_tx.tx_list, ltx->ltx_idle);

                        /* normal tx desc => wakeup anyone blocking for one */
                        if (ltx->ltx_idle == &ktoenal_data.ksnd_idle_ltx_list &&
                            waitqueue_active (&ktoenal_data.ksnd_idle_ltx_waitq))
                                wake_up (&ktoenal_data.ksnd_idle_ltx_waitq);
                }
                ktoenal_packets_transmitted++;
        }
        else
        {
                tx->tx_nob -= rc;

                spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, *irq_flags);

                /* back onto HEAD of tx_queue */
                list_add (&tx->tx_list, &conn->ksnc_tx_queue);
        }

        if (!conn->ksnc_tx_ready ||             /* no space to write now */
            list_empty (&conn->ksnc_tx_queue))  /* nothing to write */
        {
                conn->ksnc_tx_scheduled = 0;    /* not being scheduled */
                ktoenal_put_conn (conn);       /* release scheduler's ref */
        }
        else                                    /* let scheduler call me again */
                list_add_tail (&conn->ksnc_tx_list, &ktoenal_data.ksnd_tx_conns);
}

void
ktoenal_launch_packet (ksock_conn_t *conn, ksock_tx_t *tx)
{
        long          flags;
        int           nob = tx->tx_nob;
        struct iovec *iov = tx->tx_iov;
        int           niov = 1;
        
        LASSERT (nob >= sizeof (ptl_hdr_t));

        /* Truncate iov to exactly match total packet length
         * since socket sendmsg pays no attention to requested length.
         */
        for (;;)
        {
                LASSERT (niov <= tx->tx_niov);
                LASSERT (iov->iov_len >= 0);
                
                if (iov->iov_len >= nob)
                {
                        iov->iov_len = nob;
                        break;
                }
                nob -= iov->iov_len;
                iov++;
                niov++;
        }
        tx->tx_niov = niov;
        
        spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, flags);
        list_add_tail (&tx->tx_list, &conn->ksnc_tx_queue);

        if (conn->ksnc_tx_ready &&              /* able to send */
            !conn->ksnc_tx_scheduled)           /* not scheduled to send */
        {
                list_add_tail (&conn->ksnc_tx_list, &ktoenal_data.ksnd_tx_conns);
                conn->ksnc_tx_scheduled = 1;
                atomic_inc (&conn->ksnc_refcount); /* extra ref for scheduler */
                if (waitqueue_active (&ktoenal_data.ksnd_sched_waitq))
                        wake_up (&ktoenal_data.ksnd_sched_waitq);
        }

        ktoenal_packets_launched++;
        spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);
}

int
ktoenal_send(nal_cb_t *nal, void *private, lib_msg_t *cookie,
              ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
              unsigned int payload_niov, struct iovec *payload_iov, size_t payload_len)
{
        ptl_nid_t     gatewaynid;
        ksock_conn_t *conn;
        ksock_ltx_t  *ltx;
        int           rc;
        int           i;

        /* By this point, as it happens, we have absolutely no idea what
         * 'private' is.  It might be ksock_nal_data or it might be ksock_conn.
         * Ha ha, isn't that a funny joke?
         *
         * FIXME: this is not the right way to fix this; the right way is to
         * always pass in the same kind of structure.  This is hard right now.
         * To revisit this issue, set a breakpoint in here and watch for when
         * it's called from lib_finalize.  I think this occurs when we send a
         * packet as a side-effect of another packet, such as when an ACK has
         * been requested. -phil */

        CDEBUG(D_NET, "sending %d bytes from [%d](%p,%d)... to nid: "
               LPX64" pid %d\n", (int)payload_len, payload_niov,
               payload_niov > 0 ? payload_iov[0].iov_base : NULL,
               (int)(payload_niov > 0 ? payload_iov[0].iov_len : 0), nid, pid);

        if ((conn = ktoenal_get_conn (nid)) == NULL)
        {
                /* It's not a peer; try to find a gateway */
                rc = kpr_lookup (&ktoenal_data.ksnd_router, nid, &gatewaynid);
                if (rc != 0)
                {
                        CERROR ("Can't route to "LPX64": router error %d\n", nid, rc);
                        return (-1);
                }

                if ((conn = ktoenal_get_conn (gatewaynid)) == NULL)
                {
                        CERROR ("Can't route to "LPX64": gateway "LPX64" is not a peer\n", 
                                nid, gatewaynid);
                        return (-1);
                }
        }

        /* This transmit has now got a ref on conn */

        /* I may not block for a transmit descriptor if I might block the
         * receiver, or an interrupt handler. */
        ltx = ktoenal_get_ltx (!(type == PTL_MSG_ACK ||
                                 type == PTL_MSG_REPLY ||
                                 in_interrupt ()));
        if (ltx == NULL)
        {
                CERROR ("Can't allocate tx desc\n");
                ktoenal_put_conn (conn);
                return (-1);
        }
        
        /* Init common (to sends and forwards) packet part */
        ltx->ltx_tx.tx_isfwd = 0;
        ltx->ltx_tx.tx_nob = sizeof (*hdr) + payload_len;
        ltx->ltx_tx.tx_niov = 1 + payload_niov;
        ltx->ltx_tx.tx_iov = ltx->ltx_iov;

        /* Init local send packet (storage for hdr, finalize() args, iov) */
        ltx->ltx_hdr = *hdr;
        ltx->ltx_private = private;
        ltx->ltx_cookie = cookie;

        ltx->ltx_iov[0].iov_base = &ltx->ltx_hdr;
        ltx->ltx_iov[0].iov_len = sizeof (ltx->ltx_hdr);

        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        for (i = 0; i < payload_niov; i++)
        {
                ltx->ltx_iov[1 + i].iov_base = payload_iov[i].iov_base;
                ltx->ltx_iov[1 + i].iov_len  = payload_iov[i].iov_len;
        }

        ktoenal_launch_packet (conn, &ltx->ltx_tx);
        return (0);
}

void
ktoenal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        ksock_conn_t *conn;
        ptl_nid_t     nid = fwd->kprfd_gateway_nid;
        ksock_tx_t   *tx  = (ksock_tx_t *)&fwd->kprfd_scratch;

        CDEBUG (D_NET, "Forwarding [%p] -> "LPX64" ("LPX64"))\n", fwd, 
                fwd->kprfd_gateway_nid, fwd->kprfd_target_nid);

        if (nid == ktoenal_lib.ni.nid)         /* I'm the gateway; must be the last hop */
                nid = fwd->kprfd_target_nid;
        
        conn = ktoenal_get_conn (nid);
        if (conn == NULL)
        {
                CERROR ("[%p] fwd to "LPX64" isn't a peer\n", fwd, nid);
                kpr_fwd_done (&ktoenal_data.ksnd_router, fwd, -EHOSTUNREACH);
                return;
        }

        /* This forward has now got a ref on conn */

        tx->tx_isfwd = 1;                       /* This is a forwarding packet */
        tx->tx_nob   = fwd->kprfd_nob;
        tx->tx_niov  = fwd->kprfd_niov;
        tx->tx_iov   = fwd->kprfd_iov;

        ktoenal_launch_packet (conn, tx);
}

int
ktoenal_thread_start (int (*fn)(void *arg), void *arg)
{
        long    pid = kernel_thread (fn, arg, 0);

        if (pid < 0)
                return ((int)pid);

        atomic_inc (&ktoenal_data.ksnd_nthreads);
        return (0);
}

void
ktoenal_thread_fini (void)
{
        atomic_dec (&ktoenal_data.ksnd_nthreads);
}

void
ktoenal_fmb_callback (void *arg, int error)
{
        ksock_fmb_t       *fmb = (ksock_fmb_t *)arg;
        ptl_hdr_t         *hdr = (ptl_hdr_t *) page_address(fmb->fmb_pages[0]);
        ksock_conn_t      *conn;
        long               flags;

        CDEBUG (D_NET, "routed packet from "LPX64" to "LPX64": %d\n", 
                hdr->src_nid, hdr->dest_nid, error);

        if (error != 0)
                CERROR ("Failed to route packet from "LPX64" to "LPX64": %d\n", 
                        hdr->src_nid, hdr->dest_nid, error);

        spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, flags);
        
        list_add (&fmb->fmb_list, &fmb->fmb_pool->fmp_idle_fmbs);

        if (!list_empty (&fmb->fmb_pool->fmp_blocked_conns))
        {
                conn = list_entry (fmb->fmb_pool->fmp_blocked_conns.next, ksock_conn_t, ksnc_rx_list);
                list_del (&conn->ksnc_rx_list);

                CDEBUG (D_NET, "Scheduling conn %p\n", conn);
                LASSERT (conn->ksnc_rx_scheduled);
                LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_FMB_SLEEP);

                conn->ksnc_rx_state = SOCKNAL_RX_GET_FMB;
                list_add_tail (&conn->ksnc_rx_list, &ktoenal_data.ksnd_rx_conns);

                if (waitqueue_active (&ktoenal_data.ksnd_sched_waitq))
                        wake_up (&ktoenal_data.ksnd_sched_waitq);
        }

        spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);
}

ksock_fmb_t *
ktoenal_get_idle_fmb (ksock_conn_t *conn)
{
        /* NB called with sched lock held */
        int               payload_nob = conn->ksnc_rx_nob_left;
        int               packet_nob = sizeof (ptl_hdr_t) + payload_nob;
        ksock_fmb_pool_t *pool;
        ksock_fmb_t      *fmb;
        
        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_GET_FMB);

        if (packet_nob <= SOCKNAL_SMALL_FWD_PAGES * PAGE_SIZE)
                pool = &ktoenal_data.ksnd_small_fmp;
        else
                pool = &ktoenal_data.ksnd_large_fmp;
        
        if (!list_empty (&pool->fmp_idle_fmbs))
        {
                fmb = list_entry (pool->fmp_idle_fmbs.next, ksock_fmb_t, fmb_list);
                list_del (&fmb->fmb_list);
                return (fmb);
        }

        /* deschedule until fmb free */

        conn->ksnc_rx_state = SOCKNAL_RX_FMB_SLEEP;

        list_add_tail (&conn->ksnc_rx_list,
                       &pool->fmp_blocked_conns);
        return (NULL);
}


int
ktoenal_init_fmb (ksock_conn_t *conn, ksock_fmb_t *fmb)
{
        int payload_nob = conn->ksnc_rx_nob_left;
        int packet_nob = sizeof (ptl_hdr_t) + payload_nob;
        int niov;                               /* at least the header */
        int nob;
        
        LASSERT (conn->ksnc_rx_scheduled);
        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_GET_FMB);
        LASSERT (conn->ksnc_rx_nob_wanted == conn->ksnc_rx_nob_left);
        LASSERT (payload_nob >= 0);
        LASSERT (packet_nob <= fmb->fmb_npages * PAGE_SIZE);
        LASSERT (sizeof (ptl_hdr_t) < PAGE_SIZE);
        
        /* Got a forwarding buffer; copy the header we just read into the
         * forwarding buffer.  If there's payload start reading reading it
         * into the buffer, otherwise the forwarding buffer can be kicked
         * off immediately.
         *
         * NB fmb->fmb_iov spans the WHOLE packet.
         *    conn->ksnc_rx_iov spans just the payload.
         */

        fmb->fmb_iov[0].iov_base = page_address (fmb->fmb_pages[0]);
                
        memcpy (fmb->fmb_iov[0].iov_base, &conn->ksnc_hdr, sizeof (ptl_hdr_t)); /* copy header */

        if (payload_nob == 0)                   /* got complete packet already */
        {
                atomic_inc (&ktoenal_packets_received);

                CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d fwd_start (immediate)\n", conn,
                        conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid, packet_nob);

                fmb->fmb_iov[0].iov_len = sizeof (ptl_hdr_t);

                kpr_fwd_init (&fmb->fmb_fwd, conn->ksnc_hdr.dest_nid, 
                              packet_nob, 1, fmb->fmb_iov, 
                              ktoenal_fmb_callback, fmb);

                kpr_fwd_start (&ktoenal_data.ksnd_router, &fmb->fmb_fwd); /* forward it now */

                ktoenal_new_packet (conn, 0);  /* on to next packet */
                return (1);
        }

        niov = 1;
        if (packet_nob <= PAGE_SIZE)            /* whole packet fits in first page */
                fmb->fmb_iov[0].iov_len = packet_nob;
        else
        {
                fmb->fmb_iov[0].iov_len = PAGE_SIZE;
                nob = packet_nob - PAGE_SIZE;
                
                do
                {
                        LASSERT (niov < fmb->fmb_npages);
                        fmb->fmb_iov[niov].iov_base = page_address (fmb->fmb_pages[niov]);
                        fmb->fmb_iov[niov].iov_len = MIN (PAGE_SIZE, nob);
                        nob -= PAGE_SIZE;
                        niov++;
                } while (nob > 0);
        }

        kpr_fwd_init (&fmb->fmb_fwd, conn->ksnc_hdr.dest_nid, 
                      packet_nob, niov, fmb->fmb_iov, 
                      ktoenal_fmb_callback, fmb);

        /* stash router's descriptor ready for call to kpr_fwd_start */        
        conn->ksnc_cookie = &fmb->fmb_fwd;

        conn->ksnc_rx_state = SOCKNAL_RX_BODY_FWD; /* read in the payload */

        /* payload is desc's iov-ed buffer, but skipping the hdr */
        LASSERT (niov <= sizeof (conn->ksnc_rx_iov) / sizeof (conn->ksnc_rx_iov[0]));

        conn->ksnc_rx_iov[0].iov_base = (void *)(((unsigned long)fmb->fmb_iov[0].iov_base) + sizeof (ptl_hdr_t));
        conn->ksnc_rx_iov[0].iov_len = fmb->fmb_iov[0].iov_len - sizeof (ptl_hdr_t);

        if (niov > 1)
                memcpy (&conn->ksnc_rx_iov[1], &fmb->fmb_iov[1], (niov - 1) * sizeof (struct iovec));

        conn->ksnc_rx_niov = niov;

        CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d reading body\n", conn,
                conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid, payload_nob);
        return (0);
}

void
ktoenal_fwd_parse (ksock_conn_t *conn)
{
        ksock_conn_t *conn2;
        int           body_len;

        CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d parsing header\n", conn,
                conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid, conn->ksnc_rx_nob_left);

        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_HEADER);
        LASSERT (conn->ksnc_rx_scheduled);

        switch (conn->ksnc_hdr.type)
        {
        case PTL_MSG_GET:
        case PTL_MSG_ACK:
                body_len = 0;
                break;
        case PTL_MSG_PUT:
                body_len = conn->ksnc_hdr.msg.put.length;
                break;
        case PTL_MSG_REPLY:
                body_len = conn->ksnc_hdr.msg.reply.length;
                break;
        default:
                /* Unrecognised packet type */
                CERROR ("Unrecognised packet type %d from "LPX64" for "LPX64"\n",
                        conn->ksnc_hdr.type, conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid);
                /* Ignore this header and go back to reading a new packet. */
                ktoenal_new_packet (conn, 0);
                return;
        }

        if (body_len < 0)                               /* length corrupt */
        {
                CERROR ("dropping packet from "LPX64" for "LPX64": packet size %d illegal\n",
                        conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid, body_len);
                ktoenal_new_packet (conn, 0);          /* on to new packet */
                return;
        }

        if (body_len > SOCKNAL_MAX_FWD_PAYLOAD)         /* too big to forward */
        {
                CERROR ("dropping packet from "LPX64" for "LPX64": packet size %d too big\n",
                        conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid, body_len);
                ktoenal_new_packet (conn, body_len);    /* on to new packet (skip this one's body) */
                return;
        }

        conn2 = ktoenal_get_conn (conn->ksnc_hdr.dest_nid); /* should have gone direct */
        if (conn2 != NULL)
        {
                CERROR ("dropping packet from "LPX64" for "LPX64": target is a peer\n",
                        conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid);
                ktoenal_put_conn (conn2);          /* drop ref from get above */

                ktoenal_new_packet (conn, body_len);  /* on to next packet (skip this one's body) */
                return;
        }

        conn->ksnc_rx_state = SOCKNAL_RX_GET_FMB;       /* Getting FMB now */
        conn->ksnc_rx_nob_left = body_len;              /* stash packet size */
        conn->ksnc_rx_nob_wanted = body_len;            /* (no slop) */
}

int
ktoenal_new_packet (ksock_conn_t *conn, int nob_to_skip)
{
        static char ktoenal_slop_buffer[4096];

        int   nob;
        int   niov;
        int   skipped;

        if (nob_to_skip == 0)                   /* right at next packet boundary now */
        {
                conn->ksnc_rx_state = SOCKNAL_RX_HEADER;
                conn->ksnc_rx_nob_wanted = sizeof (ptl_hdr_t);
                conn->ksnc_rx_nob_left = sizeof (ptl_hdr_t);

                conn->ksnc_rx_iov[0].iov_base = (char *)&conn->ksnc_hdr;
                conn->ksnc_rx_iov[0].iov_len  = sizeof (ptl_hdr_t);
                conn->ksnc_rx_niov = 1;
                return (1);
        }

        /* set up to skip as much a possible now */
        /* if there's more left (ran out of iov entries) we'll get called again */

        conn->ksnc_rx_state = SOCKNAL_RX_SLOP;
        conn->ksnc_rx_nob_left = nob_to_skip;
        skipped = 0;
        niov = 0;

        do
        {
                nob = MIN (nob_to_skip, sizeof (ktoenal_slop_buffer));

                conn->ksnc_rx_iov[niov].iov_base = ktoenal_slop_buffer;
                conn->ksnc_rx_iov[niov].iov_len  = nob;
                niov++;
                skipped += nob;
                nob_to_skip -=nob;

        } while (nob_to_skip != 0 &&            /* mustn't overflow conn's rx iov */
                 niov < sizeof (conn->ksnc_rx_iov)/sizeof (conn->ksnc_rx_iov[0]));

        conn->ksnc_rx_niov = niov;
        conn->ksnc_rx_nob_wanted = skipped;
        return (0);
}

void
ktoenal_process_receive (ksock_conn_t *conn, long *irq_flags)
{
        ksock_fmb_t *fmb;
        int          len;
        LASSERT (atomic_read (&conn->ksnc_refcount) > 0);
        LASSERT (conn->ksnc_rx_scheduled);
        LASSERT (conn->ksnc_rx_ready);

        /* NB: sched lock held */
        CDEBUG(D_NET, "conn %p\n", conn);

        if (conn->ksnc_rx_state != SOCKNAL_RX_GET_FMB)     /* doesn't need a forwarding buffer */
        {
                spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, *irq_flags);
                goto try_read;
        }

 get_fmb:
        /* NB: sched lock held */
        fmb = ktoenal_get_idle_fmb (conn);
        if (fmb == NULL)                        /* conn descheduled waiting for idle fmb */
                return;

        spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, *irq_flags);
        
        if (ktoenal_init_fmb (conn, fmb)) /* packet forwarded ? */
                goto out;               /* come back later for next packet */

 try_read:
        /* NB: sched lock NOT held */
        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_HEADER ||
                 conn->ksnc_rx_state == SOCKNAL_RX_BODY ||
                 conn->ksnc_rx_state == SOCKNAL_RX_BODY_FWD ||
                 conn->ksnc_rx_state == SOCKNAL_RX_SLOP);

        LASSERT (conn->ksnc_rx_niov > 0);
        LASSERT (conn->ksnc_rx_nob_wanted > 0);

        conn->ksnc_rx_ready = 0;                /* data ready may race with me and set ready */
        mb();                                   /* => clear BEFORE trying to read */

        /* NB ktoenal_recvmsg "consumes" the iov passed to it */
        len = ktoenal_recvmsg(conn->ksnc_file,
                               conn->ksnc_rx_iov, conn->ksnc_rx_niov,
                               conn->ksnc_rx_nob_wanted);
        CDEBUG (D_NET, "%p read(%d) %d\n", conn, conn->ksnc_rx_nob_wanted, len);

        if (len <= 0)                           /* nothing ready (EAGAIN) or EOF or error */
        {
                if (len != -EAGAIN &&           /* ! nothing to read now */
                    len != 0)                   /* ! nothing to read ever */
                {
#warning FIXME: handle socket errors properly
                        CERROR ("Error socknal read(%d) %p: %d\n",
                                conn->ksnc_rx_nob_wanted, conn, len);
                }
                goto out;                       /* come back when there's data ready */
        }

        LASSERT (len <= conn->ksnc_rx_nob_wanted);
        conn->ksnc_rx_nob_wanted -= len;
        conn->ksnc_rx_nob_left -= len;

        if (conn->ksnc_rx_nob_wanted != 0)      /* short read */
                goto out;                       /* try again later */

        conn->ksnc_rx_ready = 1;                /* assume there's more to be had */

        switch (conn->ksnc_rx_state)
        {
        case SOCKNAL_RX_HEADER:
                if (conn->ksnc_hdr.dest_nid != ktoenal_lib.ni.nid) /* It's not for me */
                {
                        ktoenal_fwd_parse (conn);
                        switch (conn->ksnc_rx_state)
                        {
                        case SOCKNAL_RX_HEADER: /* skipped this packet (zero payload) */
                                goto out;       /* => come back later */
                        case SOCKNAL_RX_SLOP:   /* skipping this packet's body */
                                goto try_read;  /* => go read it */
                        case SOCKNAL_RX_GET_FMB: /* forwarding */
                                spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, *irq_flags);
                                goto get_fmb;   /* => go get a fwd msg buffer */
                        default:
                        }
                        /* Not Reached */
                        LBUG ();
                }

                PROF_START(lib_parse);
                lib_parse(&ktoenal_lib, &conn->ksnc_hdr, conn); /* sets wanted_len, iovs etc */
                PROF_FINISH(lib_parse);

                if (conn->ksnc_rx_nob_wanted != 0) /* need to get some payload? */
                {
                        conn->ksnc_rx_state = SOCKNAL_RX_BODY;
                        goto try_read;          /* go read the payload */
                }
                /* Fall through (completed packet for me) */

        case SOCKNAL_RX_BODY:
                atomic_inc (&ktoenal_packets_received);
                lib_finalize(&ktoenal_lib, NULL, conn->ksnc_cookie); /* packet is done now */
                /* Fall through */

        case SOCKNAL_RX_SLOP:
                if (ktoenal_new_packet (conn, conn->ksnc_rx_nob_left)) /* starting new packet? */
                        goto out;               /* come back later */
                goto try_read;                  /* try to finish reading slop now */

        case SOCKNAL_RX_BODY_FWD:
                CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d fwd_start (got body)\n", conn,
                        conn->ksnc_hdr.src_nid, conn->ksnc_hdr.dest_nid, conn->ksnc_rx_nob_left);

                atomic_inc (&ktoenal_packets_received);

                /* ktoenal_init_fmb() stashed router descriptor in conn->ksnc_cookie */
                kpr_fwd_start (&ktoenal_data.ksnd_router, (kpr_fwd_desc_t *)conn->ksnc_cookie);

                LASSERT (conn->ksnc_rx_nob_left == 0); /* no slop in forwarded packets */

                ktoenal_new_packet (conn, 0);  /* on to next packet */
                goto out;                       /* (later) */

        default:
        }

        /* Not Reached */
        LBUG ();

 out:
        spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, *irq_flags);

        if (!conn->ksnc_rx_ready)               /* no data there to read? */
        {
                conn->ksnc_rx_scheduled = 0;    /* let socket callback schedule again */
                ktoenal_put_conn (conn);       /* release scheduler's ref */
        }
        else                                    /* let scheduler call me again */
                list_add_tail (&conn->ksnc_rx_list, &ktoenal_data.ksnd_rx_conns);
}

int
ktoenal_recv(nal_cb_t *nal, void *private, lib_msg_t *msg,
             unsigned int niov, struct iovec *iov, size_t mlen, size_t rlen)
{
        ksock_conn_t *conn = (ksock_conn_t *)private;
        int           i;

        conn->ksnc_cookie = msg;

        LASSERT (niov <= PTL_MD_MAX_IOV);
        for (i = 0; i < niov; i++)
        {
                conn->ksnc_rx_iov[i].iov_len = iov[i].iov_len;
                conn->ksnc_rx_iov[i].iov_base = iov[i].iov_base;
        }

        conn->ksnc_rx_niov       = niov;
        conn->ksnc_rx_nob_wanted = mlen;
        conn->ksnc_rx_nob_left   = rlen;

        return (rlen);
}

int
ktoenal_scheduler (void *arg)
{
        unsigned long      flags;
        ksock_conn_t      *conn;
        int                rc;
        int                nloops = 0;

        kportal_daemonize ("ktoenal_sched");
        kportal_blockallsigs ();
        
        spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, flags);

        while (!ktoenal_data.ksnd_shuttingdown)
        {
                int did_something = 0;

                /* Ensure I progress everything semi-fairly */

                if (!list_empty (&ktoenal_data.ksnd_rx_conns))
                {
                        did_something = 1;
                        conn = list_entry (ktoenal_data.ksnd_rx_conns.next,
                                           ksock_conn_t, ksnc_rx_list);
                        list_del (&conn->ksnc_rx_list);

                        ktoenal_process_receive (conn, &flags); /* drops & regains ksnd_sched_lock */
                }

                if (!list_empty (&ktoenal_data.ksnd_tx_conns))
                {
                        did_something = 1;
                        conn = list_entry (ktoenal_data.ksnd_tx_conns.next,
                                           ksock_conn_t, ksnc_tx_list);

                        list_del (&conn->ksnc_tx_list);
                        ktoenal_process_transmit (conn, &flags); /* drops and regains ksnd_sched_lock */
                }

                if (!did_something ||           /* nothing to do */
                    ++nloops == SOCKNAL_RESCHED) /* hogging CPU? */
                {
                        spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);

                        nloops = 0;

                        if (!did_something) {   /* wait for something to do */
                                rc = wait_event_interruptible (ktoenal_data.ksnd_sched_waitq,
                                                               ktoenal_data.ksnd_shuttingdown ||
                                                               !list_empty (&ktoenal_data.ksnd_rx_conns) ||
                                                               !list_empty (&ktoenal_data.ksnd_tx_conns));
                                LASSERT (rc == 0);
                        } else 
                                our_cond_resched();

                        spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, flags);
                }
        }

        spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);
        ktoenal_thread_fini ();
        return (0);
}


int
ktoenal_reaper (void *arg)
{
        unsigned long      flags;
        ksock_conn_t      *conn;
        int                rc;
        
        kportal_daemonize ("ktoenal_reaper");
        kportal_blockallsigs ();

        while (!ktoenal_data.ksnd_shuttingdown)
        {
                spin_lock_irqsave (&ktoenal_data.ksnd_reaper_lock, flags);

                if (list_empty (&ktoenal_data.ksnd_reaper_list))
                        conn = NULL;
                else
                {
                        conn = list_entry (ktoenal_data.ksnd_reaper_list.next,
                                           ksock_conn_t, ksnc_list);
                        list_del (&conn->ksnc_list);
                }

                spin_unlock_irqrestore (&ktoenal_data.ksnd_reaper_lock, flags);

                if (conn != NULL)
                        ktoenal_close_conn (conn);
                else {
                        rc = wait_event_interruptible (ktoenal_data.ksnd_reaper_waitq,
                                                       ktoenal_data.ksnd_shuttingdown ||
                                                       !list_empty(&ktoenal_data.ksnd_reaper_list));
                        LASSERT (rc == 0);
                }
        }

        ktoenal_thread_fini ();
        return (0);
}

#define POLLREAD        (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)
#define POLLWRITE       (POLLOUT | POLLWRNORM | POLLWRBAND)

int
ktoenal_pollthread(void *arg)
{
        unsigned int mask;
        struct list_head *tmp;
        ksock_conn_t *conn;
        
        /* Save the task struct for waking it up */
        ktoenal_data.ksnd_pollthread_tsk = current; 
        
        kportal_daemonize ("ktoenal_pollthread");
        kportal_blockallsigs ();
        
        poll_initwait(&ktoenal_data.ksnd_pwait);
        
        while(!ktoenal_data.ksnd_shuttingdown) {
                
                set_current_state(TASK_INTERRUPTIBLE);
                
                read_lock (&ktoenal_data.ksnd_socklist_lock);
                list_for_each(tmp, &ktoenal_data.ksnd_socklist) {
                        
                        conn = list_entry(tmp, ksock_conn_t, ksnc_list);
                        atomic_inc(&conn->ksnc_refcount);
                        read_unlock (&ktoenal_data.ksnd_socklist_lock);
                        
                        mask = conn->ksnc_file->f_op->poll(conn->ksnc_file,
                                  ktoenal_data.ksnd_slistchange ? 
                                  &ktoenal_data.ksnd_pwait : NULL);
                         
                        if(mask & POLLREAD) {
                                ktoenal_data_ready(conn);
                                                        
                        } 
                        if (mask & POLLWRITE) {
                                ktoenal_write_space(conn);  
                              
                        }
                        if (mask & (POLLERR | POLLHUP)) {
                                         /* Do error processing */          
                        }      
                        
                        read_lock (&ktoenal_data.ksnd_socklist_lock);
                        if(atomic_dec_and_test(&conn->ksnc_refcount))
                                _ktoenal_put_conn(conn);
                }
                ktoenal_data.ksnd_slistchange = 0;
                read_unlock (&ktoenal_data.ksnd_socklist_lock);
                
                schedule_timeout(MAX_SCHEDULE_TIMEOUT);
                if(ktoenal_data.ksnd_slistchange) {
                        poll_freewait(&ktoenal_data.ksnd_pwait); 
                        poll_initwait(&ktoenal_data.ksnd_pwait);
                }
         }
        poll_freewait(&ktoenal_data.ksnd_pwait);
        ktoenal_thread_fini();
        return (0);
}

void
ktoenal_data_ready (ksock_conn_t *conn)
{
        unsigned long  flags;
        ENTRY;

        if (!test_and_set_bit (0, &conn->ksnc_rx_ready)) { 
                spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, flags);

                if (!conn->ksnc_rx_scheduled) {  /* not being progressed */
                        list_add_tail (&conn->ksnc_rx_list, 
                                        &ktoenal_data.ksnd_rx_conns);
                        conn->ksnc_rx_scheduled = 1;
                        /* extra ref for scheduler */
                        atomic_inc (&conn->ksnc_refcount);

                        /* This is done to avoid the effects of a sequence
                         * of events in which the rx_ready is lost
                         */
                        conn->ksnc_rx_ready=1;
                          
                        if (waitqueue_active (&ktoenal_data.ksnd_sched_waitq))
                                wake_up (&ktoenal_data.ksnd_sched_waitq);
                }

                spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);
        }

        EXIT;
}

void
ktoenal_write_space (ksock_conn_t *conn)
{
        unsigned long  flags;

        CDEBUG (D_NET, "conn %p%s%s%s\n",
                         conn,
                        (conn == NULL) ? "" : (test_bit (0, &conn->ksnc_tx_ready) ? " ready" : " blocked"),
                        (conn == NULL) ? "" : (conn->ksnc_tx_scheduled ? " scheduled" : " idle"),
                        (conn == NULL) ? "" : (list_empty (&conn->ksnc_tx_queue) ? " empty" : " queued"));


        if (!test_and_set_bit (0, &conn->ksnc_tx_ready)) {
                spin_lock_irqsave (&ktoenal_data.ksnd_sched_lock, flags);

                if (!list_empty (&conn->ksnc_tx_queue) && /* packets to send */
                                !conn->ksnc_tx_scheduled) { /* not being progressed */

                        list_add_tail (&conn->ksnc_tx_list, 
                                        &ktoenal_data.ksnd_tx_conns);
                        conn->ksnc_tx_scheduled = 1;
                        /* extra ref for scheduler */
                        atomic_inc (&conn->ksnc_refcount);

                        if (waitqueue_active (&ktoenal_data.ksnd_sched_waitq))
                                wake_up (&ktoenal_data.ksnd_sched_waitq);
                }
                spin_unlock_irqrestore (&ktoenal_data.ksnd_sched_lock, flags);
        }
}

nal_cb_t ktoenal_lib = {
        nal_data:       &ktoenal_data,                /* NAL private data */
        cb_send:         ktoenal_send,
        cb_recv:         ktoenal_recv,
        cb_read:         ktoenal_read,
        cb_write:        ktoenal_write,
        cb_callback:     ktoenal_callback,
        cb_malloc:       ktoenal_malloc,
        cb_free:         ktoenal_free,
        cb_printf:       ktoenal_printf,
        cb_cli:          ktoenal_cli,
        cb_sti:          ktoenal_sti,
        cb_dist:         ktoenal_dist
};
