/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@zabbo.net>
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
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
 */

#include "socknal.h"

atomic_t   ksocknal_packets_received;
atomic_t   ksocknal_packets_launched;
atomic_t   ksocknal_packets_being_sent;

#if SOCKNAL_ZC
int        ksocknal_do_zc = 1;
int        ksocknal_zc_min_frag = 2048;
#endif

/*
 *  LIB functions follow
 *
 */
int
ksocknal_read(nal_cb_t *nal, void *private, void *dst_addr,
              user_ptr src_addr, size_t len)
{
        CDEBUG(D_NET, LPX64": reading %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr);

        memcpy( dst_addr, src_addr, len );
        return 0;
}

int
ksocknal_write(nal_cb_t *nal, void *private, user_ptr dst_addr,
               void *src_addr, size_t len)
{
        CDEBUG(D_NET, LPX64": writing %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr);

        memcpy( dst_addr, src_addr, len );
        return 0;
}

int
ksocknal_callback (nal_cb_t * nal, void *private, lib_eq_t *eq,
                         ptl_event_t *ev)
{
        CDEBUG(D_NET, LPX64": callback eq %p ev %p\n",
               nal->ni.nid, eq, ev);

        if (eq->event_callback != NULL)
                eq->event_callback(ev);

        return 0;
}

void *
ksocknal_malloc(nal_cb_t *nal, size_t len)
{
        void *buf;

        PORTAL_ALLOC(buf, len);

        if (buf != NULL)
                memset(buf, 0, len);

        return (buf);
}

void
ksocknal_free(nal_cb_t *nal, void *buf, size_t len)
{
        PORTAL_FREE(buf, len);
}

void
ksocknal_printf(nal_cb_t *nal, const char *fmt, ...)
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
ksocknal_cli(nal_cb_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *data = nal->nal_data;

        spin_lock(&data->ksnd_nal_cb_lock);
}

void
ksocknal_sti(nal_cb_t *nal, unsigned long *flags)
{
        ksock_nal_data_t *data;
        data = nal->nal_data;

        spin_unlock(&data->ksnd_nal_cb_lock);
}

int
ksocknal_dist(nal_cb_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        /* I would guess that if ksocknal_get_conn(nid) == NULL,
           and we're not routing, then 'nid' is very distant :) */
        if ( nal->ni.nid == nid ) {
                *dist = 0;
        } else {
                *dist = 1;
        }

        return 0;
}

ksock_ltx_t *
ksocknal_get_ltx (int may_block)
{
        unsigned long flags;
        ksock_ltx_t *ltx = NULL;

        for (;;) {
                spin_lock_irqsave (&ksocknal_data.ksnd_idle_ltx_lock, flags);

                if (!list_empty (&ksocknal_data.ksnd_idle_ltx_list)) {
                        ltx = list_entry(ksocknal_data.ksnd_idle_ltx_list.next,
                                         ksock_ltx_t, ltx_tx.tx_list);
                        list_del (&ltx->ltx_tx.tx_list);
                        break;
                }

                if (!may_block) {
                        if (!list_empty(&ksocknal_data.ksnd_idle_nblk_ltx_list)) {
                                ltx = list_entry(ksocknal_data.ksnd_idle_nblk_ltx_list.next,
                                                 ksock_ltx_t, ltx_tx.tx_list);
                                list_del (&ltx->ltx_tx.tx_list);
                        }
                        break;
                }

                spin_unlock_irqrestore(&ksocknal_data.ksnd_idle_ltx_lock,
                                       flags);

                wait_event (ksocknal_data.ksnd_idle_ltx_waitq,
                            !list_empty (&ksocknal_data.ksnd_idle_ltx_list));
        }

        spin_unlock_irqrestore (&ksocknal_data.ksnd_idle_ltx_lock, flags);

        return (ltx);
}

#if SOCKNAL_ZC
struct page *
ksocknal_kvaddr_to_page (unsigned long vaddr)
{
        struct page *page;

        if (vaddr >= VMALLOC_START &&
            vaddr < VMALLOC_END)
                page = vmalloc_to_page ((void *)vaddr);
#if CONFIG_HIGHMEM
        else if (vaddr >= PKMAP_BASE &&
                 vaddr < (PKMAP_BASE + LAST_PKMAP * PAGE_SIZE))
                page = vmalloc_to_page ((void *)vaddr);
                /* in 2.4 ^ just walks the page tables */
#endif
        else
                page = virt_to_page (vaddr);

        if (page == NULL ||
            !VALID_PAGE (page))
                return (NULL);

        return (page);
}
#endif

int
ksocknal_send_iov (struct socket *sock, ksock_tx_t *tx, int more)
{
        struct iovec  *iov = tx->tx_iov;
        int            fragsize = iov->iov_len;
        unsigned long  vaddr = (unsigned long)iov->iov_base;
#if SOCKNAL_ZC
        int            offset = vaddr & (PAGE_SIZE - 1);
        int            zcsize = MIN (fragsize, PAGE_SIZE - offset);
        struct page   *page;
#endif
        int            rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only send 1 frag at a time. */
        LASSERT (fragsize <= tx->tx_nob);
        LASSERT (tx->tx_niov > 0);
        more |= (tx->tx_niov > 1);
        
#if SOCKNAL_ZC
        if (ksocknal_do_zc &&
            (sock->sk->route_caps & NETIF_F_SG) &&
            (sock->sk->route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)) &&
            zcsize >= ksocknal_zc_min_frag &&
            (page = ksocknal_kvaddr_to_page (vaddr)) != NULL) {
                
                CDEBUG(D_NET, "vaddr %p, page %p->%p + offset %x for %d\n",
                       (void *)vaddr, page, page_address(page), offset, zcsize);

                more |= (zcsize < fragsize);

                rc = tcp_sendpage_zccd(sock, page, offset, zcsize, 
                                       more ? (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT,
                                       &tx->tx_zccd);
        } else
#endif
        {
                /* NB don't pass tx's iov; sendmsg may or may not update it */
                struct iovec fragiov = { .iov_base = (void *)vaddr,
                                         .iov_len  = fragsize};
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &fragiov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = more ? (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT
                };
                mm_segment_t oldmm = get_fs();
                
                set_fs (KERNEL_DS);
                rc = sock_sendmsg(sock, &msg, fragsize);
                set_fs (oldmm);
        } 

        if (rc <= 0)
                return (rc);

        tx->tx_nob -= rc;

        if (rc < fragsize) {
                /* didn't send whole frag */
                iov->iov_base = (void *)(vaddr + rc);
                iov->iov_len  = fragsize - rc;
                return (-EAGAIN);
        }

        /* everything went */
        LASSERT (rc == fragsize);
        tx->tx_iov++;
        tx->tx_niov--;
        return (1);
}

int
ksocknal_send_kiov (struct socket *sock, ksock_tx_t *tx, int more)
{
        ptl_kiov_t    *kiov = tx->tx_kiov;
        int            fragsize = kiov->kiov_len;
        struct page   *page = kiov->kiov_page;
        int            offset = kiov->kiov_offset;
        int            rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only send 1 frag at a time. */
        LASSERT (fragsize <= tx->tx_nob);
        LASSERT (offset + fragsize <= PAGE_SIZE);
        LASSERT (tx->tx_nkiov > 0);
        more |= (tx->tx_nkiov > 1);

#if SOCKNAL_ZC
        if (ksocknal_do_zc &&
            (sock->sk->route_caps & NETIF_F_SG) &&
            (sock->sk->route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)) &&
            fragsize >= ksocknal_zc_min_frag) {

                CDEBUG(D_NET, "page %p + offset %x for %d\n",
                               page, offset, fragsize);

                rc = tcp_sendpage_zccd(sock, page, offset, fragsize,
                                       more ? (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT,
                                       &tx->tx_zccd);
        } else
#endif
        {
                char *addr = ((char *)kmap (page)) + offset;
                struct iovec fragiov = {.iov_base = addr,
                                        .iov_len  = fragsize};
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &fragiov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = more ? (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT
                };
                mm_segment_t  oldmm = get_fs();
                
                set_fs (KERNEL_DS);
                rc = sock_sendmsg(sock, &msg, fragsize);
                set_fs (oldmm);
                kunmap (page);
        }

        if (rc <= 0)
                return (rc);

        tx->tx_nob -= rc;

        if (rc < fragsize) {
                /* didn't send whole frag */
                kiov->kiov_offset = offset + rc;
                kiov->kiov_len    = fragsize - rc;
                return (-EAGAIN);
        }

        /* everything went */
        LASSERT (rc == fragsize);
        tx->tx_kiov++;
        tx->tx_nkiov--;
        return (1);
}

int
ksocknal_sendmsg (struct socket *sock, ksock_tx_t *tx, int more)
{
        int    rc;
        int    sent_some = 0;
        ENTRY;
        
        LASSERT (!in_interrupt());

        for (;;) {
                if (tx->tx_niov != 0)
                        rc = ksocknal_send_iov (sock, tx, more || tx->tx_nkiov != 0);
                else
                        rc = ksocknal_send_kiov (sock, tx, more);

                /* Interpret a zero rc the same as -EAGAIN (Adaptech TOE) */
                if (rc <= 0)                    /* error or partial send */
                        RETURN ((sent_some || rc == -EAGAIN) ? 0 : rc);
                
                if (tx->tx_nob == 0)            /* sent everything */
                        RETURN (0);

                sent_some = 1;
        }
}

int
ksocknal_recv_iov (ksock_conn_t *conn)
{
        struct iovec *iov = conn->ksnc_rx_iov;
        int           fragsize  = iov->iov_len;
        unsigned long vaddr = (unsigned long)iov->iov_base;
        struct iovec  fragiov = { .iov_base = (void *)vaddr,
                                  .iov_len  = fragsize};
        struct msghdr msg = {
                .msg_name       = NULL,
                .msg_namelen    = 0,
                .msg_iov        = &fragiov,
                .msg_iovlen     = 1,
                .msg_control    = NULL,
                .msg_controllen = 0,
                .msg_flags      = 0
        };
        mm_segment_t oldmm = get_fs();
        int          rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only receive 1 frag at a time. */
        LASSERT (conn->ksnc_rx_niov > 0);
        LASSERT (fragsize <= conn->ksnc_rx_nob_wanted);
        
        set_fs (KERNEL_DS);
        rc = sock_recvmsg (conn->ksnc_sock, &msg, fragsize, MSG_DONTWAIT);
        /* NB this is just a boolean............................^ */
        set_fs (oldmm);

        if (rc <= 0)
                return (rc);

        conn->ksnc_rx_nob_wanted -= rc;
        conn->ksnc_rx_nob_left -= rc;
                
        if (rc < fragsize) {
                iov->iov_base = (void *)(vaddr + rc);
                iov->iov_len = fragsize - rc;
                return (-EAGAIN);
        }

        LASSERT (rc == fragsize);
        conn->ksnc_rx_iov++;
        conn->ksnc_rx_niov--;
        return (1);
}

int
ksocknal_recv_kiov (ksock_conn_t *conn)
{
        ptl_kiov_t   *kiov = conn->ksnc_rx_kiov;
        struct page  *page = kiov->kiov_page;
        int           offset = kiov->kiov_offset;
        int           fragsize = kiov->kiov_len;
        unsigned long vaddr = ((unsigned long)kmap (page)) + offset;
        struct iovec  fragiov = { .iov_base = (void *)vaddr,
                                  .iov_len  = fragsize};
        struct msghdr msg = {
                .msg_name       = NULL,
                .msg_namelen    = 0,
                .msg_iov        = &fragiov,
                .msg_iovlen     = 1,
                .msg_control    = NULL,
                .msg_controllen = 0,
                .msg_flags      = 0
        };
        mm_segment_t oldmm = get_fs();
        int          rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only receive 1 frag at a time. */
        LASSERT (fragsize <= conn->ksnc_rx_nob_wanted);
        LASSERT (conn->ksnc_rx_nkiov > 0);
        LASSERT (offset + fragsize <= PAGE_SIZE);
        
        set_fs (KERNEL_DS);
        rc = sock_recvmsg (conn->ksnc_sock, &msg, fragsize, MSG_DONTWAIT);
        /* NB this is just a boolean............................^ */
        set_fs (oldmm);
        kunmap (page);
        
        if (rc <= 0)
                return (rc);
        
        conn->ksnc_rx_nob_wanted -= rc;
        conn->ksnc_rx_nob_left -= rc;
                
        if (rc < fragsize) {
                kiov->kiov_offset = offset + rc;
                kiov->kiov_len = fragsize - rc;
                return (-EAGAIN);
        }

        LASSERT (rc == fragsize);
        conn->ksnc_rx_kiov++;
        conn->ksnc_rx_nkiov--;
        return (1);
}

int
ksocknal_recvmsg (ksock_conn_t *conn) 
{
        int    rc;
        int    got_some = 0;
        ENTRY;
        
        LASSERT (!in_interrupt ());

        for (;;) {
                LASSERT (conn->ksnc_rx_nob_wanted > 0);
                
                if (conn->ksnc_rx_niov != 0)
                        rc = ksocknal_recv_iov (conn);
                else
                        rc = ksocknal_recv_kiov (conn);

                /* CAVEAT EMPTOR: we return...
                 * <= 0 for error (0 == EOF) and > 0 for success (unlike sendmsg()) */

                if (rc <= 0)                    /* error/EOF or partial receive */
                        RETURN ((got_some || rc == -EAGAIN) ? 1 : rc);
                
                if (conn->ksnc_rx_nob_wanted == 0)
                        RETURN (1);

                got_some = 0;
        }
}

#if SOCKNAL_ZC
void
ksocknal_zc_callback (zccd_t *zcd)
{
        ksock_tx_t    *tx = KSOCK_ZCCD_2_TX(zcd);
        ksock_sched_t *sched = tx->tx_sched;
        unsigned long  flags;
        ENTRY;

        /* Schedule tx for cleanup (can't do it now due to lock conflicts) */

        spin_lock_irqsave (&sched->kss_lock, flags);

        list_add_tail (&tx->tx_list, &sched->kss_zctxdone_list);
        if (waitqueue_active (&sched->kss_waitq))
                wake_up (&sched->kss_waitq);

        spin_unlock_irqrestore (&sched->kss_lock, flags);
        EXIT;
}
#endif

void
ksocknal_tx_done (ksock_tx_t *tx)
{
        unsigned long flags;
        ksock_ltx_t   *ltx;
        ENTRY;

        atomic_dec (&ksocknal_packets_being_sent);

        if (tx->tx_isfwd) {             /* was a forwarded packet? */
                kpr_fwd_done (&ksocknal_data.ksnd_router,
                              KSOCK_TX_2_KPR_FWD_DESC (tx), 0);
                EXIT;
                return;
        }

        /* local send */
        ltx = KSOCK_TX_2_KSOCK_LTX (tx);

        lib_finalize (&ksocknal_lib, ltx->ltx_private, ltx->ltx_cookie);

        spin_lock_irqsave (&ksocknal_data.ksnd_idle_ltx_lock, flags);

        list_add_tail (&ltx->ltx_tx.tx_list, ltx->ltx_idle);

        /* normal tx desc => wakeup anyone blocking for one */
        if (ltx->ltx_idle == &ksocknal_data.ksnd_idle_ltx_list &&
            waitqueue_active (&ksocknal_data.ksnd_idle_ltx_waitq))
                wake_up (&ksocknal_data.ksnd_idle_ltx_waitq);

        spin_unlock_irqrestore (&ksocknal_data.ksnd_idle_ltx_lock, flags);
        EXIT;
}

void
ksocknal_process_transmit (ksock_sched_t *sched, unsigned long *irq_flags)
{
        ksock_conn_t *conn;
        ksock_tx_t *tx;
        int         rc;

        LASSERT (!list_empty (&sched->kss_tx_conns));
        conn = list_entry(sched->kss_tx_conns.next, ksock_conn_t, ksnc_tx_list);
        list_del (&conn->ksnc_tx_list);

        LASSERT (conn->ksnc_tx_scheduled);
        LASSERT (conn->ksnc_tx_ready);
        LASSERT (!list_empty (&conn->ksnc_tx_queue));
        tx = list_entry (conn->ksnc_tx_queue.next, ksock_tx_t, tx_list);
        /* assume transmit will complete now, so dequeue while I've got lock */
        list_del (&tx->tx_list);

        spin_unlock_irqrestore (&sched->kss_lock, *irq_flags);

        LASSERT (tx->tx_nob > 0);

        conn->ksnc_tx_ready = 0;/* write_space may race with me and set ready */
        mb();                   /* => clear BEFORE trying to write */

        rc = ksocknal_sendmsg (conn->ksnc_sock, tx, 
                               !list_empty (&conn->ksnc_tx_queue)); /* more to come? */

        CDEBUG (D_NET, "send(%d) %d\n", tx->tx_nob, rc);

        if (rc != 0) {
#warning FIXME: handle socket errors properly
                CERROR("Error socknal send(%d) %p: %d\n", tx->tx_nob, conn, rc);
                /* kid on for now the whole packet went.
                 * NB when we handle the error better, we'll still need to
                 * block for zccd completion.
                 */
                tx->tx_nob = 0;
        }

        if (tx->tx_nob == 0)                    /* nothing left to send */
        {
                /* everything went; assume more can go, so prevent write_space locking */
                conn->ksnc_tx_ready = 1;

                ksocknal_put_conn (conn);       /* release packet's ref */
                atomic_inc (&ksocknal_packets_being_sent);
#if SOCKNAL_ZC
                if (atomic_read (&tx->tx_zccd.zccd_count) != 1) {
                        /* zccd skbufs are still in-flight.  Release my
                         * initial ref on zccd, so callback can occur */
                        zccd_put (&tx->tx_zccd);
                } else
#endif
                        ksocknal_tx_done (tx);

                spin_lock_irqsave (&sched->kss_lock, *irq_flags);
        } else {
                spin_lock_irqsave (&sched->kss_lock, *irq_flags);

                /* back onto HEAD of tx_queue */
                list_add (&tx->tx_list, &conn->ksnc_tx_queue);
        }

        if (!conn->ksnc_tx_ready ||             /* no space to write now */
            list_empty (&conn->ksnc_tx_queue)) {/* nothing to write */
                conn->ksnc_tx_scheduled = 0;    /* not being scheduled */
                ksocknal_put_conn (conn);       /* release scheduler's ref */
        } else                                 /* let scheduler call me again */
                list_add_tail (&conn->ksnc_tx_list, &sched->kss_tx_conns);
}

void
ksocknal_launch_packet (ksock_conn_t *conn, ksock_tx_t *tx)
{
        unsigned long  flags;
        ksock_sched_t *sched = conn->ksnc_scheduler;

        /* Ensure the frags we've been given EXACTLY match the number of
         * bytes we want to send.  Many TCP/IP stacks disregard any total
         * size parameters passed to them and just look at the frags. 
         *
         * We always expect at least 1 mapped fragment containing the
         * complete portals header.
         */
        LASSERT (lib_iov_nob (tx->tx_niov, tx->tx_iov) +
                 lib_kiov_nob (tx->tx_nkiov, tx->tx_kiov) == tx->tx_nob);
        LASSERT (tx->tx_niov >= 1);
        LASSERT (tx->tx_iov[0].iov_len >= sizeof (ptl_hdr_t));
        
        CDEBUG (D_NET, "type %d, nob %d niov %d nkiov %d\n",
                ((ptl_hdr_t *)tx->tx_iov[0].iov_base)->type, tx->tx_nob, 
                tx->tx_niov, tx->tx_nkiov);

#if SOCKNAL_ZC
        zccd_init (&tx->tx_zccd, ksocknal_zc_callback);
        /* NB this sets 1 ref on zccd, so the callback can only occur
         * after I've released this ref */
        tx->tx_sched = sched;
#endif
        spin_lock_irqsave (&sched->kss_lock, flags);

        list_add_tail (&tx->tx_list, &conn->ksnc_tx_queue);

        if (conn->ksnc_tx_ready &&              /* able to send */
            !conn->ksnc_tx_scheduled) {          /* not scheduled to send */
                list_add_tail (&conn->ksnc_tx_list, &sched->kss_tx_conns);
                conn->ksnc_tx_scheduled = 1;
                atomic_inc (&conn->ksnc_refcount); /* extra ref for scheduler */
                if (waitqueue_active (&sched->kss_waitq))
                        wake_up (&sched->kss_waitq);
        }

        spin_unlock_irqrestore (&sched->kss_lock, flags);

        atomic_inc (&ksocknal_packets_launched);
}

ksock_conn_t *
ksocknal_send_target (ptl_nid_t nid) 
{
        ptl_nid_t     gatewaynid;
        ksock_conn_t *conn;
        int           rc;

        if ((conn = ksocknal_get_conn (nid)) == NULL) {
                /* It's not a peer; try to find a gateway */
                rc = kpr_lookup (&ksocknal_data.ksnd_router, nid, &gatewaynid);
                if (rc != 0) {
                        CERROR("Can't route to "LPX64": router error %d\n",
                               nid, rc);
                        return (NULL);
                }

                if ((conn = ksocknal_get_conn (gatewaynid)) == NULL) {
                        CERROR ("Can't route to "LPX64": gateway "LPX64
                                " is not a peer\n", nid, gatewaynid);
                        return (NULL);
                }
        }

        return (conn);
}

ksock_ltx_t *
ksocknal_setup_hdr (nal_cb_t *nal, void *private, lib_msg_t *cookie, 
                    ptl_hdr_t *hdr, int type)
{
        ksock_ltx_t  *ltx;

        /* I may not block for a transmit descriptor if I might block the
         * receiver, or an interrupt handler. */
        ltx = ksocknal_get_ltx (!(type == PTL_MSG_ACK ||
                                  type == PTL_MSG_REPLY ||
                                  in_interrupt ()));
        if (ltx == NULL) {
                CERROR ("Can't allocate tx desc\n");
                return (NULL);
        }

        /* Init local send packet (storage for hdr, finalize() args) */
        ltx->ltx_hdr = *hdr;
        ltx->ltx_private = private;
        ltx->ltx_cookie = cookie;
        
        /* Init common ltx_tx */
        ltx->ltx_tx.tx_isfwd = 0;
        ltx->ltx_tx.tx_nob = sizeof (*hdr);

        /* We always have 1 mapped frag for the header */
        ltx->ltx_tx.tx_niov = 1;
        ltx->ltx_tx.tx_iov = &ltx->ltx_iov_space.hdr;
        ltx->ltx_tx.tx_iov[0].iov_base = &ltx->ltx_hdr;
        ltx->ltx_tx.tx_iov[0].iov_len = sizeof (ltx->ltx_hdr);

        ltx->ltx_tx.tx_kiov  = NULL;
        ltx->ltx_tx.tx_nkiov = 0;

        return (ltx);
}

int
ksocknal_send (nal_cb_t *nal, void *private, lib_msg_t *cookie,
               ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
               unsigned int payload_niov, struct iovec *payload_iov,
               size_t payload_len)
{
        ksock_ltx_t  *ltx;
        ksock_conn_t *conn;

        /* NB 'private' is different depending on what we're sending.
         * Just ignore it until we can rely on it
         *
         * Also, the return code from this procedure is ignored.
         * If we can't send, we must still complete with lib_finalize().
         * We'll have to wait for 3.2 to return an error event.
         */

        CDEBUG(D_NET,
               "sending "LPSZ" bytes in %d mapped frags to nid: "LPX64
               " pid %d\n", payload_len, payload_niov, nid, pid);

        conn = ksocknal_send_target (nid);
        if (conn == NULL) {
                lib_finalize (&ksocknal_lib, private, cookie);
                return (-1);
        }

        ltx = ksocknal_setup_hdr (nal, private, cookie, hdr, type);
        if (ltx == NULL) {
                ksocknal_put_conn (conn);
                lib_finalize (&ksocknal_lib, private, cookie);
                return (-1);
        }

        /* append the payload_iovs to the one pointing at the header */
        LASSERT (ltx->ltx_tx.tx_niov == 1 && ltx->ltx_tx.tx_nkiov == 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        memcpy (ltx->ltx_tx.tx_iov + 1, payload_iov,
                payload_niov * sizeof (*payload_iov));
        ltx->ltx_tx.tx_niov = 1 + payload_niov;
        ltx->ltx_tx.tx_nob = sizeof (*hdr) + payload_len;

        ksocknal_launch_packet (conn, &ltx->ltx_tx);
        return (0);
}

int
ksocknal_send_pages (nal_cb_t *nal, void *private, lib_msg_t *cookie, 
                     ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                     unsigned int payload_niov, ptl_kiov_t *payload_iov, size_t payload_len)
{
        ksock_ltx_t *ltx;
        ksock_conn_t *conn;
        
        /* NB 'private' is different depending on what we're sending.
         * Just ignore it until we can rely on it */

        CDEBUG(D_NET,
               "sending "LPSZ" bytes in %d mapped frags to nid: "LPX64" pid %d\n",
               payload_len, payload_niov, nid, pid);

        conn = ksocknal_send_target (nid);
        if (conn == NULL)
                return (-1);

        ltx = ksocknal_setup_hdr (nal, private, cookie, hdr, type);
        if (ltx == NULL) {
                ksocknal_put_conn (conn);
                return (-1);
        }

        LASSERT (ltx->ltx_tx.tx_niov == 1 && ltx->ltx_tx.tx_nkiov == 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);
        
        ltx->ltx_tx.tx_kiov = ltx->ltx_iov_space.payload.kiov;
        memcpy (ltx->ltx_tx.tx_kiov, payload_iov, 
                payload_niov * sizeof (*payload_iov));
        ltx->ltx_tx.tx_nkiov = payload_niov;
        ltx->ltx_tx.tx_nob = sizeof (*hdr) + payload_len;

        ksocknal_launch_packet (conn, &ltx->ltx_tx);
        return (0);
}

void
ksocknal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        ksock_conn_t *conn;
        ptl_nid_t     nid = fwd->kprfd_gateway_nid;
        ksock_tx_t   *tx  = (ksock_tx_t *)&fwd->kprfd_scratch;

        CDEBUG (D_NET, "Forwarding [%p] -> "LPX64" ("LPX64"))\n", fwd,
                fwd->kprfd_gateway_nid, fwd->kprfd_target_nid);

        /* I'm the gateway; must be the last hop */
        if (nid == ksocknal_lib.ni.nid)
                nid = fwd->kprfd_target_nid;

        conn = ksocknal_get_conn (nid);
        if (conn == NULL) {
                CERROR ("[%p] fwd to "LPX64" isn't a peer\n", fwd, nid);
                kpr_fwd_done (&ksocknal_data.ksnd_router, fwd, -EHOSTUNREACH);
                return;
        }

        /* This forward has now got a ref on conn */

        tx->tx_isfwd = 1;                   /* This is a forwarding packet */
        tx->tx_nob   = fwd->kprfd_nob;
        tx->tx_niov  = fwd->kprfd_niov;
        tx->tx_iov   = fwd->kprfd_iov;
        tx->tx_nkiov = 0;
        tx->tx_kiov  = NULL;
        
        ksocknal_launch_packet (conn, tx);
}

int
ksocknal_thread_start (int (*fn)(void *arg), void *arg)
{
        long    pid = kernel_thread (fn, arg, 0);

        if (pid < 0)
                return ((int)pid);

        atomic_inc (&ksocknal_data.ksnd_nthreads);
        return (0);
}

void
ksocknal_thread_fini (void)
{
        atomic_dec (&ksocknal_data.ksnd_nthreads);
}

void
ksocknal_fmb_callback (void *arg, int error)
{
        ksock_fmb_t       *fmb = (ksock_fmb_t *)arg;
        ksock_fmb_pool_t  *fmp = fmb->fmb_pool;
        ptl_hdr_t         *hdr = (ptl_hdr_t *) page_address(fmb->fmb_pages[0]);
        ksock_conn_t      *conn = NULL;
        ksock_sched_t     *sched;
        unsigned long      flags;

        if (error != 0)
                CERROR("Failed to route packet from "LPX64" to "LPX64": %d\n",
                       NTOH__u64(hdr->src_nid), NTOH__u64(hdr->dest_nid),
                       error);
        else
                CDEBUG (D_NET, "routed packet from "LPX64" to "LPX64": OK\n",
                        NTOH__u64 (hdr->src_nid), NTOH__u64 (hdr->dest_nid));

        spin_lock_irqsave (&fmp->fmp_lock, flags);

        list_add (&fmb->fmb_list, &fmp->fmp_idle_fmbs);

        if (!list_empty (&fmp->fmp_blocked_conns)) {
                conn = list_entry (fmb->fmb_pool->fmp_blocked_conns.next,
                                   ksock_conn_t, ksnc_rx_list);
                list_del (&conn->ksnc_rx_list);
        }

        spin_unlock_irqrestore (&fmp->fmp_lock, flags);

        if (conn == NULL)
                return;

        CDEBUG (D_NET, "Scheduling conn %p\n", conn);
        LASSERT (conn->ksnc_rx_scheduled);
        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_FMB_SLEEP);

        conn->ksnc_rx_state = SOCKNAL_RX_GET_FMB;

        sched = conn->ksnc_scheduler;

        spin_lock_irqsave (&sched->kss_lock, flags);

        list_add_tail (&conn->ksnc_rx_list, &sched->kss_rx_conns);

        if (waitqueue_active (&sched->kss_waitq))
                wake_up (&sched->kss_waitq);

        spin_unlock_irqrestore (&sched->kss_lock, flags);
}

ksock_fmb_t *
ksocknal_get_idle_fmb (ksock_conn_t *conn)
{
        int               payload_nob = conn->ksnc_rx_nob_left;
        int               packet_nob = sizeof (ptl_hdr_t) + payload_nob;
        unsigned long     flags;
        ksock_fmb_pool_t *pool;
        ksock_fmb_t      *fmb;

        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_GET_FMB);
        LASSERT (ksocknal_data.ksnd_fmbs != NULL);

        if (packet_nob <= SOCKNAL_SMALL_FWD_PAGES * PAGE_SIZE)
                pool = &ksocknal_data.ksnd_small_fmp;
        else
                pool = &ksocknal_data.ksnd_large_fmp;

        spin_lock_irqsave (&pool->fmp_lock, flags);

        if (!list_empty (&pool->fmp_idle_fmbs)) {
                fmb = list_entry(pool->fmp_idle_fmbs.next,
                                 ksock_fmb_t, fmb_list);
                list_del (&fmb->fmb_list);
                spin_unlock_irqrestore (&pool->fmp_lock, flags);

                return (fmb);
        }

        /* deschedule until fmb free */

        conn->ksnc_rx_state = SOCKNAL_RX_FMB_SLEEP;

        list_add_tail (&conn->ksnc_rx_list,
                       &pool->fmp_blocked_conns);

        spin_unlock_irqrestore (&pool->fmp_lock, flags);
        return (NULL);
}


int
ksocknal_init_fmb (ksock_conn_t *conn, ksock_fmb_t *fmb)
{
        int payload_nob = conn->ksnc_rx_nob_left;
        int packet_nob = sizeof (ptl_hdr_t) + payload_nob;
        ptl_nid_t dest_nid = NTOH__u64 (conn->ksnc_hdr.dest_nid);
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

        /* copy header */
        memcpy (fmb->fmb_iov[0].iov_base, &conn->ksnc_hdr, sizeof (ptl_hdr_t));

        if (payload_nob == 0) {         /* got complete packet already */
                atomic_inc (&ksocknal_packets_received);

                CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d fwd_start (immediate)\n",
                        conn, NTOH__u64 (conn->ksnc_hdr.src_nid),
                        dest_nid, packet_nob);

                fmb->fmb_iov[0].iov_len = sizeof (ptl_hdr_t);

                kpr_fwd_init (&fmb->fmb_fwd, dest_nid,
                              packet_nob, 1, fmb->fmb_iov,
                              ksocknal_fmb_callback, fmb);

                /* forward it now */
                kpr_fwd_start (&ksocknal_data.ksnd_router, &fmb->fmb_fwd);

                ksocknal_new_packet (conn, 0);  /* on to next packet */
                return (1);
        }

        niov = 1;
        if (packet_nob <= PAGE_SIZE) {  /* whole packet fits in first page */
                fmb->fmb_iov[0].iov_len = packet_nob;
        } else {
                fmb->fmb_iov[0].iov_len = PAGE_SIZE;
                nob = packet_nob - PAGE_SIZE;

                do {
                        LASSERT (niov < fmb->fmb_npages);
                        fmb->fmb_iov[niov].iov_base =
                                page_address (fmb->fmb_pages[niov]);
                        fmb->fmb_iov[niov].iov_len = MIN (PAGE_SIZE, nob);
                        nob -= PAGE_SIZE;
                        niov++;
                } while (nob > 0);
        }

        kpr_fwd_init (&fmb->fmb_fwd, dest_nid,
                      packet_nob, niov, fmb->fmb_iov,
                      ksocknal_fmb_callback, fmb);

        /* stash router's descriptor ready for call to kpr_fwd_start */
        conn->ksnc_cookie = &fmb->fmb_fwd;

        conn->ksnc_rx_state = SOCKNAL_RX_BODY_FWD; /* read in the payload */

        /* payload is desc's iov-ed buffer, but skipping the hdr */
        LASSERT (niov <= sizeof (conn->ksnc_rx_iov_space) /
                 sizeof (struct iovec));

        conn->ksnc_rx_iov = (struct iovec *)&conn->ksnc_rx_iov_space;
        conn->ksnc_rx_iov[0].iov_base =
                (void *)(((unsigned long)fmb->fmb_iov[0].iov_base) +
                         sizeof (ptl_hdr_t));
        conn->ksnc_rx_iov[0].iov_len =
                fmb->fmb_iov[0].iov_len - sizeof (ptl_hdr_t);

        if (niov > 1)
                memcpy(&conn->ksnc_rx_iov[1], &fmb->fmb_iov[1],
                       (niov - 1) * sizeof (struct iovec));

        conn->ksnc_rx_niov = niov;

        CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d reading body\n", conn,
                NTOH__u64 (conn->ksnc_hdr.src_nid), dest_nid, payload_nob);
        return (0);
}

void
ksocknal_fwd_parse (ksock_conn_t *conn)
{
        ksock_conn_t *conn2;
        ptl_nid_t     dest_nid = NTOH__u64 (conn->ksnc_hdr.dest_nid);
        int           body_len = NTOH__u32 (PTL_HDR_LENGTH(&conn->ksnc_hdr));

        CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d parsing header\n", conn,
                NTOH__u64 (conn->ksnc_hdr.src_nid),
                dest_nid, conn->ksnc_rx_nob_left);

        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_HEADER);
        LASSERT (conn->ksnc_rx_scheduled);

        if (body_len < 0) {                 /* length corrupt (overflow) */
                CERROR("dropping packet from "LPX64" for "LPX64": packet "
                       "size %d illegal\n", NTOH__u64 (conn->ksnc_hdr.src_nid),
                       dest_nid, body_len);
                ksocknal_new_packet (conn, 0);          /* on to new packet */
                return;
        }

        if (ksocknal_data.ksnd_fmbs == NULL) {        /* not forwarding */
                CERROR("dropping packet from "LPX64" for "LPX64": not "
                       "forwarding\n", conn->ksnc_hdr.src_nid,
                       conn->ksnc_hdr.dest_nid);
                /* on to new packet (skip this one's body) */
                ksocknal_new_packet (conn, body_len);
                return;
        }

        if (body_len > SOCKNAL_MAX_FWD_PAYLOAD) {      /* too big to forward */
                CERROR ("dropping packet from "LPX64" for "LPX64
                        ": packet size %d too big\n", conn->ksnc_hdr.src_nid,
                        conn->ksnc_hdr.dest_nid, body_len);
                /* on to new packet (skip this one's body) */
                ksocknal_new_packet (conn, body_len);
                return;
        }

        /* should have gone direct */
        conn2 = ksocknal_get_conn (conn->ksnc_hdr.dest_nid);
        if (conn2 != NULL) {
                CERROR ("dropping packet from "LPX64" for "LPX64
                        ": target is a peer\n", conn->ksnc_hdr.src_nid,
                        conn->ksnc_hdr.dest_nid);
                ksocknal_put_conn (conn2);  /* drop ref from get above */

                /* on to next packet (skip this one's body) */
                ksocknal_new_packet (conn, body_len);
                return;
        }

        conn->ksnc_rx_state = SOCKNAL_RX_GET_FMB;       /* Getting FMB now */
        conn->ksnc_rx_nob_left = body_len;              /* stash packet size */
        conn->ksnc_rx_nob_wanted = body_len;            /* (no slop) */
}

int
ksocknal_new_packet (ksock_conn_t *conn, int nob_to_skip)
{
        static char ksocknal_slop_buffer[4096];

        int   nob;
        int   niov;
        int   skipped;

        if (nob_to_skip == 0) {         /* right at next packet boundary now */
                conn->ksnc_rx_state = SOCKNAL_RX_HEADER;
                conn->ksnc_rx_nob_wanted = sizeof (ptl_hdr_t);
                conn->ksnc_rx_nob_left = sizeof (ptl_hdr_t);

                conn->ksnc_rx_iov = (struct iovec *)&conn->ksnc_rx_iov_space;
                conn->ksnc_rx_iov[0].iov_base = (char *)&conn->ksnc_hdr;
                conn->ksnc_rx_iov[0].iov_len  = sizeof (ptl_hdr_t);
                conn->ksnc_rx_niov = 1;

                conn->ksnc_rx_kiov = NULL;
                conn->ksnc_rx_nkiov = 0;
                return (1);
        }

        /* Set up to skip as much a possible now.  If there's more left
         * (ran out of iov entries) we'll get called again */

        conn->ksnc_rx_state = SOCKNAL_RX_SLOP;
        conn->ksnc_rx_nob_left = nob_to_skip;
        conn->ksnc_rx_iov = (struct iovec *)&conn->ksnc_rx_iov_space;
        skipped = 0;
        niov = 0;

        do {
                nob = MIN (nob_to_skip, sizeof (ksocknal_slop_buffer));

                conn->ksnc_rx_iov[niov].iov_base = ksocknal_slop_buffer;
                conn->ksnc_rx_iov[niov].iov_len  = nob;
                niov++;
                skipped += nob;
                nob_to_skip -=nob;

        } while (nob_to_skip != 0 &&    /* mustn't overflow conn's rx iov */
                 niov < sizeof(conn->ksnc_rx_iov_space) / sizeof (struct iovec));

        conn->ksnc_rx_niov = niov;
        conn->ksnc_rx_kiov = NULL;
        conn->ksnc_rx_nkiov = 0;
        conn->ksnc_rx_nob_wanted = skipped;
        return (0);
}

void
ksocknal_process_receive (ksock_sched_t *sched, unsigned long *irq_flags)
{
        ksock_conn_t *conn;
        ksock_fmb_t  *fmb;
        int           rc;

        /* NB: sched->ksnc_lock lock held */

        LASSERT (!list_empty (&sched->kss_rx_conns));
        conn = list_entry(sched->kss_rx_conns.next, ksock_conn_t, ksnc_rx_list);
        list_del (&conn->ksnc_rx_list);

        spin_unlock_irqrestore (&sched->kss_lock, *irq_flags);

        CDEBUG(D_NET, "sched %p conn %p\n", sched, conn);
        LASSERT (atomic_read (&conn->ksnc_refcount) > 0);
        LASSERT (conn->ksnc_rx_scheduled);
        LASSERT (conn->ksnc_rx_ready);

        /* doesn't need a forwarding buffer */
        if (conn->ksnc_rx_state != SOCKNAL_RX_GET_FMB)
                goto try_read;

 get_fmb:
        fmb = ksocknal_get_idle_fmb (conn);
        if (fmb == NULL) {      /* conn descheduled waiting for idle fmb */
                spin_lock_irqsave (&sched->kss_lock, *irq_flags);
                return;
        }

        if (ksocknal_init_fmb (conn, fmb)) /* packet forwarded ? */
                goto out;               /* come back later for next packet */

 try_read:
        /* NB: sched lock NOT held */
        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_HEADER ||
                 conn->ksnc_rx_state == SOCKNAL_RX_BODY ||
                 conn->ksnc_rx_state == SOCKNAL_RX_BODY_FWD ||
                 conn->ksnc_rx_state == SOCKNAL_RX_SLOP);

        LASSERT (conn->ksnc_rx_nob_wanted > 0);

        conn->ksnc_rx_ready = 0;/* data ready may race with me and set ready */
        mb();                   /* => clear BEFORE trying to read */

        rc = ksocknal_recvmsg(conn);

        if (rc == 0)
                goto out;
        if (rc < 0) {
#warning FIXME: handle socket errors properly
                CERROR ("Error socknal read %p: %d\n", conn, rc);
                goto out;
        }

        if (conn->ksnc_rx_nob_wanted != 0)      /* short read */
                goto out;                       /* try again later */

        /* got all I wanted, assume there's more - prevent data_ready locking */
        conn->ksnc_rx_ready = 1;

        switch (conn->ksnc_rx_state) {
        case SOCKNAL_RX_HEADER:
                /* It's not for me */
                if (conn->ksnc_hdr.type != PTL_MSG_HELLO &&
                    NTOH__u64(conn->ksnc_hdr.dest_nid) != ksocknal_lib.ni.nid) {
                        ksocknal_fwd_parse (conn);
                        switch (conn->ksnc_rx_state) {
                        case SOCKNAL_RX_HEADER: /* skipped (zero payload) */
                                goto out;       /* => come back later */
                        case SOCKNAL_RX_SLOP:   /* skipping packet's body */
                                goto try_read;  /* => go read it */
                        case SOCKNAL_RX_GET_FMB: /* forwarding */
                                goto get_fmb;   /* => go get a fwd msg buffer */
                        default:
                                LBUG ();
                        }
                        /* Not Reached */
                }

                PROF_START(lib_parse);
                /* sets wanted_len, iovs etc */
                lib_parse(&ksocknal_lib, &conn->ksnc_hdr, conn);
                PROF_FINISH(lib_parse);

                if (conn->ksnc_rx_nob_wanted != 0) { /* need to get payload? */
                        conn->ksnc_rx_state = SOCKNAL_RX_BODY;
                        goto try_read;          /* go read the payload */
                }
                /* Fall through (completed packet for me) */

        case SOCKNAL_RX_BODY:
                atomic_inc (&ksocknal_packets_received);
                /* packet is done now */
                lib_finalize(&ksocknal_lib, NULL, conn->ksnc_cookie);
                /* Fall through */

        case SOCKNAL_RX_SLOP:
                /* starting new packet? */
                if (ksocknal_new_packet (conn, conn->ksnc_rx_nob_left))
                        goto out;       /* come back later */
                goto try_read;          /* try to finish reading slop now */

        case SOCKNAL_RX_BODY_FWD:
                CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d fwd_start (got body)\n",
                        conn, NTOH__u64 (conn->ksnc_hdr.src_nid),
                        NTOH__u64 (conn->ksnc_hdr.dest_nid),
                        conn->ksnc_rx_nob_left);

                atomic_inc (&ksocknal_packets_received);

                /* ksocknal_init_fmb() put router desc. in conn->ksnc_cookie */
                kpr_fwd_start (&ksocknal_data.ksnd_router,
                               (kpr_fwd_desc_t *)conn->ksnc_cookie);

                /* no slop in forwarded packets */
                LASSERT (conn->ksnc_rx_nob_left == 0);

                ksocknal_new_packet (conn, 0);  /* on to next packet */
                goto out;                       /* (later) */

        default:
                break;
        }

        /* Not Reached */
        LBUG ();

 out:
        spin_lock_irqsave (&sched->kss_lock, *irq_flags);

        /* no data there to read? */
        if (!conn->ksnc_rx_ready) {
                /* let socket callback schedule again */
                conn->ksnc_rx_scheduled = 0;
                ksocknal_put_conn (conn);       /* release scheduler's ref */
        } else                              /* let scheduler call me again */
                list_add_tail (&conn->ksnc_rx_list, &sched->kss_rx_conns);
}

int
ksocknal_recv (nal_cb_t *nal, void *private, lib_msg_t *msg,
               unsigned int niov, struct iovec *iov, size_t mlen, size_t rlen)
{
        ksock_conn_t *conn = (ksock_conn_t *)private;

        LASSERT (mlen <= rlen);
        LASSERT (niov <= PTL_MD_MAX_IOV);
        
        conn->ksnc_cookie = msg;
        conn->ksnc_rx_nob_wanted = mlen;
        conn->ksnc_rx_nob_left   = rlen;

        conn->ksnc_rx_nkiov = 0;
        conn->ksnc_rx_kiov = NULL;
        conn->ksnc_rx_niov = niov;
        conn->ksnc_rx_iov = conn->ksnc_rx_iov_space.iov;
        memcpy (conn->ksnc_rx_iov, iov, niov * sizeof (*iov));

        LASSERT (mlen == 
                 lib_iov_nob (conn->ksnc_rx_niov, conn->ksnc_rx_iov) +
                 lib_kiov_nob (conn->ksnc_rx_nkiov, conn->ksnc_rx_kiov));

        return (rlen);
}

int
ksocknal_recv_pages (nal_cb_t *nal, void *private, lib_msg_t *msg,
                     unsigned int niov, ptl_kiov_t *kiov, size_t mlen, size_t rlen)
{
        ksock_conn_t *conn = (ksock_conn_t *)private;

        LASSERT (mlen <= rlen);
        LASSERT (niov <= PTL_MD_MAX_IOV);
        
        conn->ksnc_cookie = msg;
        conn->ksnc_rx_nob_wanted = mlen;
        conn->ksnc_rx_nob_left   = rlen;

        conn->ksnc_rx_niov = 0;
        conn->ksnc_rx_iov  = NULL;
        conn->ksnc_rx_nkiov = niov;
        conn->ksnc_rx_kiov = conn->ksnc_rx_iov_space.kiov;
        memcpy (conn->ksnc_rx_kiov, kiov, niov * sizeof (*kiov));

        LASSERT (mlen == 
                 lib_iov_nob (conn->ksnc_rx_niov, conn->ksnc_rx_iov) +
                 lib_kiov_nob (conn->ksnc_rx_nkiov, conn->ksnc_rx_kiov));

        return (rlen);
}

int ksocknal_scheduler (void *arg)
{
        ksock_sched_t     *sched = (ksock_sched_t *)arg;
        unsigned long      flags;
        int                rc;
        int                nloops = 0;
        int                id = sched - ksocknal_data.ksnd_schedulers;
        char               name[16];
#if (CONFIG_SMP && CPU_AFFINITY)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        int                cpu = cpu_logical_map(id % num_online_cpus());
#else
#warning "Take care of architecure specific logical APIC map"
        int cpu = 1;    /* Have to change later. */
#endif /* LINUX_VERSION_CODE */
        
        set_cpus_allowed (current, 1 << cpu);
        id = cpu;
#endif /* CONFIG_SMP && CPU_AFFINITY */

        snprintf (name, sizeof (name),"ksocknald[%d]", id);
        kportal_daemonize (name);
        kportal_blockallsigs ();
        
        spin_lock_irqsave (&sched->kss_lock, flags);

        while (!ksocknal_data.ksnd_shuttingdown) {
                int did_something = 0;

                /* Ensure I progress everything semi-fairly */

                if (!list_empty (&sched->kss_rx_conns)) {
                        did_something = 1;
                        /* drops & regains kss_lock */
                        ksocknal_process_receive (sched, &flags);
                }

                if (!list_empty (&sched->kss_tx_conns)) {
                        did_something = 1;
                        /* drops and regains kss_lock */
                        ksocknal_process_transmit (sched, &flags);
                }
#if SOCKNAL_ZC
                if (!list_empty (&sched->kss_zctxdone_list)) {
                        ksock_tx_t *tx =
                                list_entry(sched->kss_zctxdone_list.next,
                                           ksock_tx_t, tx_list);
                        did_something = 1;

                        list_del (&tx->tx_list);
                        spin_unlock_irqrestore (&sched->kss_lock, flags);

                        ksocknal_tx_done (tx);

                        spin_lock_irqsave (&sched->kss_lock, flags);
                }
#endif
                if (!did_something ||           /* nothing to do */
                    ++nloops == SOCKNAL_RESCHED) { /* hogging CPU? */
                        spin_unlock_irqrestore (&sched->kss_lock, flags);

                        nloops = 0;

                        if (!did_something) {   /* wait for something to do */
#if SOCKNAL_ZC
                                rc = wait_event_interruptible (sched->kss_waitq,
                                                               ksocknal_data.ksnd_shuttingdown ||
                                                               !list_empty(&sched->kss_rx_conns) ||
                                                               !list_empty(&sched->kss_tx_conns) ||
                                                               !list_empty(&sched->kss_zctxdone_list));
#else
                                rc = wait_event_interruptible (sched->kss_waitq,
                                                               ksocknal_data.ksnd_shuttingdown ||
                                                               !list_empty(&sched->kss_rx_conns) ||
                                                               !list_empty(&sched->kss_tx_conns));
#endif
                                LASSERT (rc == 0);
                        } else
                               our_cond_resched();

                        spin_lock_irqsave (&sched->kss_lock, flags);
                }
        }

        spin_unlock_irqrestore (&sched->kss_lock, flags);
        ksocknal_thread_fini ();
        return (0);
}

void
ksocknal_data_ready (struct sock *sk, int n)
{
        unsigned long  flags;
        ksock_conn_t  *conn;
        ksock_sched_t *sched;
        ENTRY;

        /* interleave correctly with closing sockets... */
        read_lock (&ksocknal_data.ksnd_socklist_lock);

        conn = sk->user_data;
        if (conn == NULL) {             /* raced with ksocknal_close_sock */
                LASSERT (sk->data_ready != &ksocknal_data_ready);
                sk->data_ready (sk, n);
        } else if (!conn->ksnc_rx_ready) {        /* new news */
                /* Set ASAP in case of concurrent calls to me */
                conn->ksnc_rx_ready = 1;

                sched = conn->ksnc_scheduler;

                spin_lock_irqsave (&sched->kss_lock, flags);

                /* Set again (process_receive may have cleared while I blocked for the lock) */
                conn->ksnc_rx_ready = 1;

                if (!conn->ksnc_rx_scheduled) {  /* not being progressed */
                        list_add_tail(&conn->ksnc_rx_list,
                                      &sched->kss_rx_conns);
                        conn->ksnc_rx_scheduled = 1;
                        /* extra ref for scheduler */
                        atomic_inc (&conn->ksnc_refcount);

                        if (waitqueue_active (&sched->kss_waitq))
                                wake_up (&sched->kss_waitq);
                }

                spin_unlock_irqrestore (&sched->kss_lock, flags);
        }

        read_unlock (&ksocknal_data.ksnd_socklist_lock);

        EXIT;
}

void
ksocknal_write_space (struct sock *sk)
{
        unsigned long  flags;
        ksock_conn_t  *conn;
        ksock_sched_t *sched;

        /* interleave correctly with closing sockets... */
        read_lock (&ksocknal_data.ksnd_socklist_lock);

        conn = sk->user_data;

        CDEBUG(D_NET, "sk %p wspace %d low water %d conn %p%s%s%s\n",
               sk, tcp_wspace(sk), SOCKNAL_TX_LOW_WATER(sk), conn,
               (conn == NULL) ? "" : (conn->ksnc_tx_ready ?
                                      " ready" : " blocked"),
               (conn == NULL) ? "" : (conn->ksnc_tx_scheduled ?
                                      " scheduled" : " idle"),
               (conn == NULL) ? "" : (list_empty (&conn->ksnc_tx_queue) ?
                                      " empty" : " queued"));

        if (conn == NULL) {             /* raced with ksocknal_close_sock */
                LASSERT (sk->write_space != &ksocknal_write_space);
                sk->write_space (sk);
        } else if (tcp_wspace(sk) >= SOCKNAL_TX_LOW_WATER(sk)) { /* got enough space */
                clear_bit (SOCK_NOSPACE, &sk->socket->flags);

                if (!conn->ksnc_tx_ready) {      /* new news */
                        /* Set ASAP in case of concurrent calls to me */
                        conn->ksnc_tx_ready = 1;

                        sched = conn->ksnc_scheduler;

                        spin_lock_irqsave (&sched->kss_lock, flags);

                        /* Set again (process_transmit may have
                           cleared while I blocked for the lock) */
                        conn->ksnc_tx_ready = 1;

                        if (!conn->ksnc_tx_scheduled && // not being progressed
                            !list_empty(&conn->ksnc_tx_queue)){//packets to send
                                list_add_tail (&conn->ksnc_tx_list,
                                               &sched->kss_tx_conns);
                                conn->ksnc_tx_scheduled = 1;
                                /* extra ref for scheduler */
                                atomic_inc (&conn->ksnc_refcount);

                                if (waitqueue_active (&sched->kss_waitq))
                                        wake_up (&sched->kss_waitq);
                        }

                        spin_unlock_irqrestore (&sched->kss_lock, flags);
                }
        }

        read_unlock (&ksocknal_data.ksnd_socklist_lock);
}

int
ksocknal_reaper (void *arg)
{
        unsigned long      flags;
        ksock_conn_t      *conn;
        int                rc;
        
        kportal_daemonize ("ksocknal_reaper");
        kportal_blockallsigs ();

        while (!ksocknal_data.ksnd_shuttingdown) {
                spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);

                if (list_empty (&ksocknal_data.ksnd_reaper_list)) {
                        conn = NULL;
                } else {
                        conn = list_entry (ksocknal_data.ksnd_reaper_list.next,
                                           ksock_conn_t, ksnc_list);
                        list_del (&conn->ksnc_list);
                }

                spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

                if (conn != NULL)
                        ksocknal_close_conn (conn);
                else {
                        rc = wait_event_interruptible (ksocknal_data.ksnd_reaper_waitq,
                                                       ksocknal_data.ksnd_shuttingdown ||
                                                       !list_empty(&ksocknal_data.ksnd_reaper_list));
                        LASSERT (rc == 0);
                }
        }

        ksocknal_thread_fini ();
        return (0);
}

nal_cb_t ksocknal_lib = {
        nal_data:       &ksocknal_data,                /* NAL private data */
        cb_send:         ksocknal_send,
        cb_send_pages:   ksocknal_send_pages,
        cb_recv:         ksocknal_recv,
        cb_recv_pages:   ksocknal_recv_pages,
        cb_read:         ksocknal_read,
        cb_write:        ksocknal_write,
        cb_callback:     ksocknal_callback,
        cb_malloc:       ksocknal_malloc,
        cb_free:         ksocknal_free,
        cb_printf:       ksocknal_printf,
        cb_cli:          ksocknal_cli,
        cb_sti:          ksocknal_sti,
        cb_dist:         ksocknal_dist
};
