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
        /* I would guess that if ksocknal_get_peer (nid) == NULL,
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
                        ksocknal_data.ksnd_active_ltxs++;
                        break;
                }

                if (!may_block) {
                        if (!list_empty(&ksocknal_data.ksnd_idle_nblk_ltx_list)) {
                                ltx = list_entry(ksocknal_data.ksnd_idle_nblk_ltx_list.next,
                                                 ksock_ltx_t, ltx_tx.tx_list);
                                list_del (&ltx->ltx_tx.tx_list);
                                ksocknal_data.ksnd_active_ltxs++;
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

void
ksocknal_put_ltx (ksock_ltx_t *ltx)
{
        unsigned long   flags;
        
        spin_lock_irqsave (&ksocknal_data.ksnd_idle_ltx_lock, flags);

        ksocknal_data.ksnd_active_ltxs--;
        list_add_tail (&ltx->ltx_tx.tx_list, ltx->ltx_idle);

        /* normal tx desc => wakeup anyone blocking for one */
        if (ltx->ltx_idle == &ksocknal_data.ksnd_idle_ltx_list)
                wake_up (&ksocknal_data.ksnd_idle_ltx_waitq);

        spin_unlock_irqrestore (&ksocknal_data.ksnd_idle_ltx_lock, flags);
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
ksocknal_send_iov (ksock_conn_t *conn, ksock_tx_t *tx)
{
        struct socket *sock = conn->ksnc_sock;
        struct iovec  *iov = tx->tx_iov;
        int            fragsize = iov->iov_len;
        unsigned long  vaddr = (unsigned long)iov->iov_base;
        int            more = (tx->tx_niov > 1) || 
                              (tx->tx_nkiov > 0) ||
                              (!list_empty (&conn->ksnc_tx_queue));
#if SOCKNAL_ZC
        int            offset = vaddr & (PAGE_SIZE - 1);
        int            zcsize = MIN (fragsize, PAGE_SIZE - offset);
        struct page   *page;
#endif
        int            rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only send 1 frag at a time. */
        LASSERT (fragsize <= tx->tx_resid);
        LASSERT (tx->tx_niov > 0);
        
#if SOCKNAL_ZC
        if (zcsize >= ksocknal_data.ksnd_zc_min_frag &&
            (sock->sk->route_caps & NETIF_F_SG) &&
            (sock->sk->route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)) &&
            (page = ksocknal_kvaddr_to_page (vaddr)) != NULL) {
                
                CDEBUG(D_NET, "vaddr %p, page %p->%p + offset %x for %d\n",
                       (void *)vaddr, page, page_address(page), offset, zcsize);

                if (fragsize > zcsize) {
                        more = 1;
                        fragsize = zcsize;
                }

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

        tx->tx_resid -= rc;

        if (rc < iov->iov_len) {
                /* didn't send whole iov entry... */
                iov->iov_base = (void *)(vaddr + rc);
                iov->iov_len -= rc;
                /* ...but did we send everything we tried to send? */
                return ((rc == fragsize) ? 1 : -EAGAIN);
        }

        tx->tx_iov++;
        tx->tx_niov--;
        return (1);
}

int
ksocknal_send_kiov (ksock_conn_t *conn, ksock_tx_t *tx)
{
        struct socket *sock = conn->ksnc_sock;
        ptl_kiov_t    *kiov = tx->tx_kiov;
        int            fragsize = kiov->kiov_len;
        struct page   *page = kiov->kiov_page;
        int            offset = kiov->kiov_offset;
        int            more = (tx->tx_nkiov > 1) ||
                              (!list_empty (&conn->ksnc_tx_queue));
        int            rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only send 1 frag at a time. */
        LASSERT (fragsize <= tx->tx_resid);
        LASSERT (offset + fragsize <= PAGE_SIZE);
        LASSERT (tx->tx_niov == 0);
        LASSERT (tx->tx_nkiov > 0);

#if SOCKNAL_ZC
        if (fragsize >= ksocknal_data.ksnd_zc_min_frag &&
            (sock->sk->route_caps & NETIF_F_SG) &&
            (sock->sk->route_caps & (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM))) {

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

        tx->tx_resid -= rc;
 
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
ksocknal_sendmsg (ksock_conn_t *conn, ksock_tx_t *tx)
{
        /* Return 0 on success, < 0 on error.
         * caller checks tx_resid to determine progress/completion */
        int      rc;
        ENTRY;
        
        if (ksocknal_data.ksnd_stall_tx != 0) {
                set_current_state (TASK_UNINTERRUPTIBLE);
                schedule_timeout (ksocknal_data.ksnd_stall_tx * HZ);
        }

        rc = ksocknal_getconnsock (conn);
        if (rc != 0)
                return (rc);

        for (;;) {
                LASSERT (tx->tx_resid != 0);

                if (conn->ksnc_closing) {
                        rc = -ESHUTDOWN;
                        break;
                }

                if (tx->tx_niov != 0)
                        rc = ksocknal_send_iov (conn, tx);
                else
                        rc = ksocknal_send_kiov (conn, tx);

                if (rc <= 0) {                  /* error or socket full? */
                        /* NB: rc == 0 and rc == -EAGAIN both mean try
                         * again later (linux stack returns -EAGAIN for
                         * this, but Adaptech TOE returns 0) */
                        if (rc == -EAGAIN)
                                rc = 0;
                        break;
                }

                /* Consider the connection alive since we managed to chuck
                 * more data into it.  Really, we'd like to consider it
                 * alive only when the peer ACKs something, but
                 * write_space() only gets called back while SOCK_NOSPACE
                 * is set.  Instead, we presume peer death has occurred if
                 * the socket doesn't drain within a timout */
                conn->ksnc_tx_deadline = jiffies + 
                                         ksocknal_data.ksnd_io_timeout * HZ;
                conn->ksnc_peer->ksnp_last_alive = jiffies;

                if (tx->tx_resid == 0) {        /* sent everything */
                        rc = 0;
                        break;
                }
        }

        ksocknal_putconnsock (conn);
        RETURN (rc);
}

void
ksocknal_eager_ack (ksock_conn_t *conn)
{
        int            opt = 1;
        mm_segment_t   oldmm = get_fs();
        struct socket *sock = conn->ksnc_sock;
        
        /* Remind the socket to ACK eagerly.  If I don't, the socket might
         * think I'm about to send something it could piggy-back the ACK
         * on, introducing delay in completing zero-copy sends in my
         * peer. */

        set_fs(KERNEL_DS);
        sock->ops->setsockopt (sock, SOL_TCP, TCP_QUICKACK,
                               (char *)&opt, sizeof (opt));
        set_fs(oldmm);
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

        /* received something... */
        conn->ksnc_peer->ksnp_last_alive = jiffies;
        conn->ksnc_rx_deadline = jiffies + 
                                 ksocknal_data.ksnd_io_timeout * HZ;
        mb();                           /* order with setting rx_started */
        conn->ksnc_rx_started = 1;

        conn->ksnc_rx_nob_wanted -= rc;
        conn->ksnc_rx_nob_left -= rc;
                
        if (rc < fragsize) {
                iov->iov_base = (void *)(vaddr + rc);
                iov->iov_len = fragsize - rc;
                return (-EAGAIN);
        }

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
        
        /* received something... */
        conn->ksnc_peer->ksnp_last_alive = jiffies;
        conn->ksnc_rx_deadline = jiffies + 
                                 ksocknal_data.ksnd_io_timeout * HZ;
        mb();                           /* order with setting rx_started */
        conn->ksnc_rx_started = 1;

        conn->ksnc_rx_nob_wanted -= rc;
        conn->ksnc_rx_nob_left -= rc;
                
        if (rc < fragsize) {
                kiov->kiov_offset = offset + rc;
                kiov->kiov_len = fragsize - rc;
                return (-EAGAIN);
        }

        conn->ksnc_rx_kiov++;
        conn->ksnc_rx_nkiov--;
        return (1);
}

int
ksocknal_recvmsg (ksock_conn_t *conn) 
{
        /* Return 1 on success, 0 on EOF, < 0 on error.
         * Caller checks ksnc_rx_nob_wanted to determine
         * progress/completion. */
        int     rc;
        ENTRY;
        
        if (ksocknal_data.ksnd_stall_rx != 0) {
                set_current_state (TASK_UNINTERRUPTIBLE);
                schedule_timeout (ksocknal_data.ksnd_stall_rx * HZ);
        }

        rc = ksocknal_getconnsock (conn);
        if (rc != 0)
                return (rc);

        for (;;) {
                if (conn->ksnc_closing) {
                        rc = -ESHUTDOWN;
                        break;
                }

                if (conn->ksnc_rx_niov != 0)
                        rc = ksocknal_recv_iov (conn);
                else
                        rc = ksocknal_recv_kiov (conn);

                if (rc <= 0) {
                        /* error/EOF or partial receive */
                        if (rc == -EAGAIN) {
                                rc = 1;
                        } else if (rc == 0 && conn->ksnc_rx_started) {
                                /* EOF in the middle of a message */
                                rc = -EPROTO;
                        }
                        break;
                }

                /* Completed a fragment */

                if (conn->ksnc_rx_nob_wanted == 0) {
                        /* Completed a message segment (header or payload) */
                        if ((ksocknal_data.ksnd_eager_ack & conn->ksnc_type) != 0 &&
                            (conn->ksnc_rx_state ==  SOCKNAL_RX_BODY ||
                             conn->ksnc_rx_state == SOCKNAL_RX_BODY_FWD)) {
                                /* Remind the socket to ack eagerly... */
                                ksocknal_eager_ack(conn);
                        }
                        rc = 1;
                        break;
                }
        }

        ksocknal_putconnsock (conn);
        RETURN (rc);
}

#if SOCKNAL_ZC
void
ksocknal_zc_callback (zccd_t *zcd)
{
        ksock_tx_t    *tx = KSOCK_ZCCD_2_TX(zcd);
        ksock_sched_t *sched = tx->tx_conn->ksnc_scheduler;
        unsigned long  flags;
        ENTRY;

        /* Schedule tx for cleanup (can't do it now due to lock conflicts) */

        spin_lock_irqsave (&sched->kss_lock, flags);

        list_add_tail (&tx->tx_list, &sched->kss_zctxdone_list);
        wake_up (&sched->kss_waitq);

        spin_unlock_irqrestore (&sched->kss_lock, flags);
        EXIT;
}
#endif

void
ksocknal_tx_done (ksock_tx_t *tx, int asynch)
{
        ksock_ltx_t   *ltx;
        ENTRY;

        if (tx->tx_conn != NULL) {
                /* This tx got queued on a conn; do the accounting... */
                atomic_sub (tx->tx_nob, &tx->tx_conn->ksnc_tx_nob);
#if SOCKNAL_ZC
                /* zero copy completion isn't always from
                 * process_transmit() so it needs to keep a ref on
                 * tx_conn... */
                if (asynch)
                        ksocknal_put_conn (tx->tx_conn);
#else
                LASSERT (!asynch);
#endif
        }

        if (tx->tx_isfwd) {             /* was a forwarded packet? */
                kpr_fwd_done (&ksocknal_data.ksnd_router,
                              KSOCK_TX_2_KPR_FWD_DESC (tx), 0);
                EXIT;
                return;
        }

        /* local send */
        ltx = KSOCK_TX_2_KSOCK_LTX (tx);

        lib_finalize (&ksocknal_lib, ltx->ltx_private, ltx->ltx_cookie);

        ksocknal_put_ltx (ltx);
        EXIT;
}

void
ksocknal_tx_launched (ksock_tx_t *tx) 
{
#if SOCKNAL_ZC
        if (atomic_read (&tx->tx_zccd.zccd_count) != 1) {
                ksock_conn_t  *conn = tx->tx_conn;
                
                /* zccd skbufs are still in-flight.  First take a ref on
                 * conn, so it hangs about for ksocknal_tx_done... */
                atomic_inc (&conn->ksnc_refcount);

                /* ...then drop the initial ref on zccd, so the zero copy
                 * callback can occur */
                zccd_put (&tx->tx_zccd);
                return;
        }
#endif
        /* Any zero-copy-ness (if any) has completed; I can complete the
         * transmit now, avoiding an extra schedule */
        ksocknal_tx_done (tx, 0);
}

int
ksocknal_process_transmit (ksock_conn_t *conn, ksock_tx_t *tx)
{
        int            rc;
       
        rc = ksocknal_sendmsg (conn, tx);

        CDEBUG (D_NET, "send(%d) %d\n", tx->tx_resid, rc);
        LASSERT (rc != -EAGAIN);

        if (rc == 0) {
                /* no errors */
                if (tx->tx_resid != 0) {
                        /* didn't send everything */
                        return (-EAGAIN);
                }
                
                ksocknal_tx_launched (tx);
                return (0);
        }

        if (!conn->ksnc_closing)
                CERROR ("[%p] Error %d on write to "LPX64" ip %08x:%d\n",
                        conn, rc, conn->ksnc_peer->ksnp_nid,
                        conn->ksnc_ipaddr, conn->ksnc_port);

        ksocknal_close_conn_and_siblings (conn, rc);
        ksocknal_tx_launched (tx);

        return (-EAGAIN);
} 

void
ksocknal_launch_autoconnect_locked (ksock_route_t *route)
{
        unsigned long     flags;

        /* called holding write lock on ksnd_global_lock */

        LASSERT (!route->ksnr_deleted);
        LASSERT ((route->ksnr_connected & (1 << SOCKNAL_CONN_ANY)) == 0);
        LASSERT ((route->ksnr_connected & KSNR_TYPED_ROUTES) != KSNR_TYPED_ROUTES);
        LASSERT (!route->ksnr_connecting);
        
        if (ksocknal_data.ksnd_typed_conns)
                route->ksnr_connecting = 
                        KSNR_TYPED_ROUTES & ~route->ksnr_connected;
        else
                route->ksnr_connecting = (1 << SOCKNAL_CONN_ANY);

        atomic_inc (&route->ksnr_refcount);     /* extra ref for asynchd */
        
        spin_lock_irqsave (&ksocknal_data.ksnd_autoconnectd_lock, flags);
        
        list_add_tail (&route->ksnr_connect_list,
                       &ksocknal_data.ksnd_autoconnectd_routes);
        wake_up (&ksocknal_data.ksnd_autoconnectd_waitq);
        
        spin_unlock_irqrestore (&ksocknal_data.ksnd_autoconnectd_lock, flags);
}

ksock_peer_t *
ksocknal_find_target_peer_locked (ksock_tx_t *tx, ptl_nid_t nid)
{
        ptl_nid_t     target_nid;
        int           rc;
        ksock_peer_t *peer = ksocknal_find_peer_locked (nid);
        
        if (peer != NULL)
                return (peer);
        
        if (tx->tx_isfwd) {
                CERROR ("Can't send packet to "LPX64
                        ": routed target is not a peer\n", nid);
                return (NULL);
        }
        
        rc = kpr_lookup (&ksocknal_data.ksnd_router, nid, tx->tx_nob,
                         &target_nid);
        if (rc != 0) {
                CERROR ("Can't route to "LPX64": router error %d\n", nid, rc);
                return (NULL);
        }

        peer = ksocknal_find_peer_locked (target_nid);
        if (peer != NULL)
                return (peer);

        CERROR ("Can't send packet to "LPX64": no peer entry\n", target_nid);
        return (NULL);
}

ksock_conn_t *
ksocknal_find_conn_locked (ksock_tx_t *tx, ksock_peer_t *peer) 
{
        struct list_head *tmp;
        ksock_conn_t     *typed = NULL;
        int               tnob  = 0;
        ksock_conn_t     *fallback = NULL;
        int               fnob     = 0;
        
        /* Find the conn with the shortest tx queue */
        list_for_each (tmp, &peer->ksnp_conns) {
                ksock_conn_t *c = list_entry(tmp, ksock_conn_t, ksnc_list);
                int           nob = atomic_read(&c->ksnc_tx_nob);

                LASSERT (!c->ksnc_closing);

                if (fallback == NULL || nob < fnob) {
                        fallback = c;
                        fnob     = nob;
                }

                if (!ksocknal_data.ksnd_typed_conns)
                        continue;

                switch (c->ksnc_type) {
                default:
                        LBUG();
                case SOCKNAL_CONN_ANY:
                        break;
                case SOCKNAL_CONN_BULK_IN:
                        continue;
                case SOCKNAL_CONN_BULK_OUT:
                        if (tx->tx_nob < ksocknal_data.ksnd_min_bulk)
                                continue;
                        break;
                case SOCKNAL_CONN_CONTROL:
                        if (tx->tx_nob >= ksocknal_data.ksnd_min_bulk)
                                continue;
                        break;
                }

                if (typed == NULL || nob < tnob) {
                        typed = c;
                        tnob  = nob;
                }
        }

        /* prefer the typed selection */
        return ((typed != NULL) ? typed : fallback);
}

void
ksocknal_queue_tx_locked (ksock_tx_t *tx, ksock_conn_t *conn)
{
        unsigned long  flags;
        ksock_sched_t *sched = conn->ksnc_scheduler;

        /* called holding global lock (read or irq-write) */

        CDEBUG (D_NET, "Sending to "LPX64" on port %d\n", 
                conn->ksnc_peer->ksnp_nid, conn->ksnc_port);

        atomic_add (tx->tx_nob, &conn->ksnc_tx_nob);
        tx->tx_resid = tx->tx_nob;
        tx->tx_conn = conn;

#if SOCKNAL_ZC
        zccd_init (&tx->tx_zccd, ksocknal_zc_callback);
        /* NB this sets 1 ref on zccd, so the callback can only occur after
         * I've released this ref. */
#endif

        spin_lock_irqsave (&sched->kss_lock, flags);

        conn->ksnc_tx_deadline = jiffies + 
                                 ksocknal_data.ksnd_io_timeout * HZ;
        mb();                                   /* order with list_add_tail */

        list_add_tail (&tx->tx_list, &conn->ksnc_tx_queue);
                
        if (conn->ksnc_tx_ready &&      /* able to send */
            !conn->ksnc_tx_scheduled) { /* not scheduled to send */
                /* +1 ref for scheduler */
                atomic_inc (&conn->ksnc_refcount);
                list_add_tail (&conn->ksnc_tx_list, 
                               &sched->kss_tx_conns);
                conn->ksnc_tx_scheduled = 1;
                wake_up (&sched->kss_waitq);
        }

        spin_unlock_irqrestore (&sched->kss_lock, flags);
}

ksock_route_t *
ksocknal_find_connectable_route_locked (ksock_peer_t *peer)
{
        struct list_head  *tmp;
        ksock_route_t     *route;
        ksock_route_t     *candidate = NULL;
        int                found = 0;
        int                bits;
        
        list_for_each (tmp, &peer->ksnp_routes) {
                route = list_entry (tmp, ksock_route_t, ksnr_list);
                bits  = route->ksnr_connected;
                
                if ((bits & KSNR_TYPED_ROUTES) == KSNR_TYPED_ROUTES ||
                    (bits & (1 << SOCKNAL_CONN_ANY)) != 0 ||
                    route->ksnr_connecting != 0) {
                        /* All typed connections have been established, or
                         * an untyped connection has been established, or
                         * connections are currently being established */
                        found = 1;
                        continue;
                }

                /* too soon to retry this guy? */
                if (!time_after_eq (jiffies, route->ksnr_timeout))
                        continue;
                
                /* always do eager routes */
                if (route->ksnr_eager)
                        return (route);

                if (candidate == NULL) {
                        /* If we don't find any other route that is fully
                         * connected or connecting, the first connectable
                         * route is returned.  If it fails to connect, it
                         * will get placed at the end of the list */
                        candidate = route;
                }
        }
 
        return (found ? NULL : candidate);
}

ksock_route_t *
ksocknal_find_connecting_route_locked (ksock_peer_t *peer)
{
        struct list_head  *tmp;
        ksock_route_t     *route;

        list_for_each (tmp, &peer->ksnp_routes) {
                route = list_entry (tmp, ksock_route_t, ksnr_list);
                
                if (route->ksnr_connecting != 0)
                        return (route);
        }
        
        return (NULL);
}

int
ksocknal_launch_packet (ksock_tx_t *tx, ptl_nid_t nid)
{
        unsigned long     flags;
        ksock_peer_t     *peer;
        ksock_conn_t     *conn;
        ksock_route_t    *route;
        rwlock_t         *g_lock;
        
        /* Ensure the frags we've been given EXACTLY match the number of
         * bytes we want to send.  Many TCP/IP stacks disregard any total
         * size parameters passed to them and just look at the frags. 
         *
         * We always expect at least 1 mapped fragment containing the
         * complete portals header. */
        LASSERT (lib_iov_nob (tx->tx_niov, tx->tx_iov) +
                 lib_kiov_nob (tx->tx_nkiov, tx->tx_kiov) == tx->tx_nob);
        LASSERT (tx->tx_niov >= 1);
        LASSERT (tx->tx_iov[0].iov_len >= sizeof (ptl_hdr_t));

        CDEBUG (D_NET, "packet %p type %d, nob %d niov %d nkiov %d\n",
                tx, ((ptl_hdr_t *)tx->tx_iov[0].iov_base)->type, 
                tx->tx_nob, tx->tx_niov, tx->tx_nkiov);

        tx->tx_conn = NULL;                     /* only set when assigned a conn */

        g_lock = &ksocknal_data.ksnd_global_lock;
        read_lock (g_lock);
        
        peer = ksocknal_find_target_peer_locked (tx, nid);
        if (peer == NULL) {
                read_unlock (g_lock);
                return (-EHOSTUNREACH);
        }

        if (ksocknal_find_connectable_route_locked(peer) == NULL) {
                conn = ksocknal_find_conn_locked (tx, peer);
                if (conn != NULL) {
                        /* I've got no autoconnect routes that need to be
                         * connecting and I do have an actual connection... */
                        ksocknal_queue_tx_locked (tx, conn);
                        read_unlock (g_lock);
                        return (0);
                }
        }
        
        /* Making one or more connections; I'll need a write lock... */

        atomic_inc (&peer->ksnp_refcount);      /* +1 ref for me while I unlock */
        read_unlock (g_lock);
        write_lock_irqsave (g_lock, flags);
        
        if (peer->ksnp_closing) {               /* peer deleted as I blocked! */
                write_unlock_irqrestore (g_lock, flags);
                ksocknal_put_peer (peer);
                return (-EHOSTUNREACH);
        }
        ksocknal_put_peer (peer);               /* drop ref I got above */

        for (;;) {
                /* launch any/all autoconnections that need it */
                route = ksocknal_find_connectable_route_locked (peer);
                if (route == NULL)
                        break;

                ksocknal_launch_autoconnect_locked (route);
        }

        conn = ksocknal_find_conn_locked (tx, peer);
        if (conn != NULL) {
                /* Connection exists; queue message on it */
                ksocknal_queue_tx_locked (tx, conn);
                write_unlock_irqrestore (g_lock, flags);
                return (0);
        }

        route = ksocknal_find_connecting_route_locked (peer);
        if (route != NULL) {
                /* At least 1 connection is being established; queue the
                 * message... */
                list_add_tail (&tx->tx_list, &peer->ksnp_tx_queue);
                write_unlock_irqrestore (g_lock, flags);
                return (0);
        }
        
        write_unlock_irqrestore (g_lock, flags);
        return (-EHOSTUNREACH);
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
        int           rc;

        /* NB 'private' is different depending on what we're sending.
         * Just ignore it until we can rely on it
         */

        CDEBUG(D_NET,
               "sending "LPSZ" bytes in %d mapped frags to nid: "LPX64
               " pid %d\n", payload_len, payload_niov, nid, pid);

        ltx = ksocknal_setup_hdr (nal, private, cookie, hdr, type);
        if (ltx == NULL)
                return (PTL_FAIL);

        /* append the payload_iovs to the one pointing at the header */
        LASSERT (ltx->ltx_tx.tx_niov == 1 && ltx->ltx_tx.tx_nkiov == 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        memcpy (ltx->ltx_tx.tx_iov + 1, payload_iov,
                payload_niov * sizeof (*payload_iov));
        ltx->ltx_tx.tx_niov = 1 + payload_niov;
        ltx->ltx_tx.tx_nob = sizeof (*hdr) + payload_len;

        rc = ksocknal_launch_packet (&ltx->ltx_tx, nid);
        if (rc == 0)
                return (PTL_OK);
        
        ksocknal_put_ltx (ltx);
        return (PTL_FAIL);
}

int
ksocknal_send_pages (nal_cb_t *nal, void *private, lib_msg_t *cookie, 
                     ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                     unsigned int payload_niov, ptl_kiov_t *payload_iov, size_t payload_len)
{
        ksock_ltx_t *ltx;
        int          rc;

        /* NB 'private' is different depending on what we're sending.
         * Just ignore it until we can rely on it */

        CDEBUG(D_NET,
               "sending "LPSZ" bytes in %d mapped frags to nid: "LPX64" pid %d\n",
               payload_len, payload_niov, nid, pid);

        ltx = ksocknal_setup_hdr (nal, private, cookie, hdr, type);
        if (ltx == NULL)
                return (PTL_FAIL);

        LASSERT (ltx->ltx_tx.tx_niov == 1 && ltx->ltx_tx.tx_nkiov == 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);
        
        ltx->ltx_tx.tx_kiov = ltx->ltx_iov_space.payload.kiov;
        memcpy (ltx->ltx_tx.tx_kiov, payload_iov, 
                payload_niov * sizeof (*payload_iov));
        ltx->ltx_tx.tx_nkiov = payload_niov;
        ltx->ltx_tx.tx_nob = sizeof (*hdr) + payload_len;

        rc = ksocknal_launch_packet (&ltx->ltx_tx, nid);
        if (rc == 0)
                return (PTL_OK);

        ksocknal_put_ltx (ltx);
        return (PTL_FAIL);
}

void
ksocknal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        ptl_nid_t     nid = fwd->kprfd_gateway_nid;
        ksock_tx_t   *tx  = (ksock_tx_t *)&fwd->kprfd_scratch;
        int           rc;
        
        CDEBUG (D_NET, "Forwarding [%p] -> "LPX64" ("LPX64"))\n", fwd,
                fwd->kprfd_gateway_nid, fwd->kprfd_target_nid);

        /* I'm the gateway; must be the last hop */
        if (nid == ksocknal_lib.ni.nid)
                nid = fwd->kprfd_target_nid;

        tx->tx_isfwd = 1;                   /* This is a forwarding packet */
        tx->tx_nob   = fwd->kprfd_nob;
        tx->tx_niov  = fwd->kprfd_niov;
        tx->tx_iov   = fwd->kprfd_iov;
        tx->tx_nkiov = 0;
        tx->tx_kiov  = NULL;
        tx->tx_hdr   = (ptl_hdr_t *)fwd->kprfd_iov[0].iov_base;

        rc = ksocknal_launch_packet (tx, nid);
        if (rc != 0)
                kpr_fwd_done (&ksocknal_data.ksnd_router, fwd, rc);
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

        /* drop peer ref taken on init */
        ksocknal_put_peer (fmb->fmb_peer);
        
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
         * forwarding buffer.  If there's payload, start reading reading it
         * into the buffer, otherwise the forwarding buffer can be kicked
         * off immediately.
         *
         * NB fmb->fmb_iov spans the WHOLE packet.
         *    conn->ksnc_rx_iov spans just the payload.
         */
        fmb->fmb_iov[0].iov_base = page_address (fmb->fmb_pages[0]);

        /* copy header */
        memcpy (fmb->fmb_iov[0].iov_base, &conn->ksnc_hdr, sizeof (ptl_hdr_t));

        /* Take a ref on the conn's peer to prevent module unload before
         * forwarding completes.  NB we ref peer and not conn since because
         * all refs on conn after it has been closed must remove themselves
         * in finite time */
        fmb->fmb_peer = conn->ksnc_peer;
        atomic_inc (&conn->ksnc_peer->ksnp_refcount);

        if (payload_nob == 0) {         /* got complete packet already */
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

        conn->ksnc_cookie = fmb;                /* stash fmb for later */
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
        ksock_peer_t *peer;
        ptl_nid_t     dest_nid = NTOH__u64 (conn->ksnc_hdr.dest_nid);
        ptl_nid_t     src_nid = NTOH__u64 (conn->ksnc_hdr.src_nid);
        int           body_len = NTOH__u32 (conn->ksnc_hdr.payload_length);
        char str[PTL_NALFMT_SIZE];

        CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d parsing header\n", conn,
                src_nid, dest_nid, conn->ksnc_rx_nob_left);

        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_HEADER);
        LASSERT (conn->ksnc_rx_scheduled);

        if (body_len < 0) {                 /* length corrupt (overflow) */
                CERROR("dropping packet from "LPX64" (%s) for "LPX64" (%s): "
                       "packet size %d illegal\n",
                       src_nid, portals_nid2str(TCPNAL, src_nid, str),
                       dest_nid, portals_nid2str(TCPNAL, dest_nid, str),
                       body_len);

                ksocknal_new_packet (conn, 0);  /* on to new packet */
                return;
        }

        if (ksocknal_data.ksnd_fmbs == NULL) {        /* not forwarding */
                CERROR("dropping packet from "LPX64" (%s) for "LPX64
                       " (%s): not forwarding\n",
                       src_nid, portals_nid2str(TCPNAL, src_nid, str),
                       dest_nid, portals_nid2str(TCPNAL, dest_nid, str));
                /* on to new packet (skip this one's body) */
                ksocknal_new_packet (conn, body_len);
                return;
        }

        if (body_len > PTL_MTU) {      /* too big to forward */
                CERROR ("dropping packet from "LPX64" (%s) for "LPX64
                        "(%s): packet size %d too big\n",
                        src_nid, portals_nid2str(TCPNAL, src_nid, str),
                        dest_nid, portals_nid2str(TCPNAL, dest_nid, str),
                        body_len);
                /* on to new packet (skip this one's body) */
                ksocknal_new_packet (conn, body_len);
                return;
        }

        /* should have gone direct */
        peer = ksocknal_get_peer (conn->ksnc_hdr.dest_nid);
        if (peer != NULL) {
                CERROR ("dropping packet from "LPX64" (%s) for "LPX64
                        "(%s): target is a peer\n",
                        src_nid, portals_nid2str(TCPNAL, src_nid, str),
                        dest_nid, portals_nid2str(TCPNAL, dest_nid, str));
                ksocknal_put_peer (peer);  /* drop ref from get above */

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
                conn->ksnc_rx_started = 0;
                mb ();                          /* racing with timeout thread */
                
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

int
ksocknal_process_receive (ksock_conn_t *conn)
{
        ksock_fmb_t  *fmb;
        int           rc;
        
        LASSERT (atomic_read (&conn->ksnc_refcount) > 0);

        /* doesn't need a forwarding buffer */
        if (conn->ksnc_rx_state != SOCKNAL_RX_GET_FMB)
                goto try_read;

 get_fmb:
        fmb = ksocknal_get_idle_fmb (conn);
        if (fmb == NULL) {
                /* conn descheduled waiting for idle fmb */
                return (0);
        }

        if (ksocknal_init_fmb (conn, fmb)) {
                /* packet forwarded */
                return (0);
        }

 try_read:
        /* NB: sched lock NOT held */
        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_HEADER ||
                 conn->ksnc_rx_state == SOCKNAL_RX_BODY ||
                 conn->ksnc_rx_state == SOCKNAL_RX_BODY_FWD ||
                 conn->ksnc_rx_state == SOCKNAL_RX_SLOP);

        LASSERT (conn->ksnc_rx_nob_wanted > 0);

        rc = ksocknal_recvmsg(conn);

        if (rc <= 0) {
                if (rc == 0)
                        CWARN ("[%p] EOF from "LPX64" ip %08x:%d\n",
                               conn, conn->ksnc_peer->ksnp_nid,
                               conn->ksnc_ipaddr, conn->ksnc_port);
                else if (!conn->ksnc_closing)
                        CERROR ("[%p] Error %d on read from "LPX64" ip %08x:%d\n",
                                conn, rc, conn->ksnc_peer->ksnp_nid,
                                conn->ksnc_ipaddr, conn->ksnc_port);

                ksocknal_close_conn_and_siblings (conn, rc);
                return (rc == 0 ? -ESHUTDOWN : rc);
        }

        if (conn->ksnc_rx_nob_wanted != 0) {
                /* short read */
                return (-EAGAIN);
        }
        
        switch (conn->ksnc_rx_state) {
        case SOCKNAL_RX_HEADER:
                if (conn->ksnc_hdr.type != HTON__u32(PTL_MSG_HELLO) &&
                    NTOH__u64(conn->ksnc_hdr.dest_nid) != ksocknal_lib.ni.nid) {
                        /* This packet isn't for me */
                        ksocknal_fwd_parse (conn);
                        switch (conn->ksnc_rx_state) {
                        case SOCKNAL_RX_HEADER: /* skipped (zero payload) */
                                return (0);     /* => come back later */
                        case SOCKNAL_RX_SLOP:   /* skipping packet's body */
                                goto try_read;  /* => go read it */
                        case SOCKNAL_RX_GET_FMB: /* forwarding */
                                goto get_fmb;   /* => go get a fwd msg buffer */
                        default:
                                LBUG ();
                        }
                        /* Not Reached */
                }

                /* sets wanted_len, iovs etc */
                lib_parse(&ksocknal_lib, &conn->ksnc_hdr, conn);

                if (conn->ksnc_rx_nob_wanted != 0) { /* need to get payload? */
                        conn->ksnc_rx_state = SOCKNAL_RX_BODY;
                        goto try_read;          /* go read the payload */
                }
                /* Fall through (completed packet for me) */

        case SOCKNAL_RX_BODY:
                /* payload all received */
                lib_finalize(&ksocknal_lib, NULL, conn->ksnc_cookie);
                /* Fall through */

        case SOCKNAL_RX_SLOP:
                /* starting new packet? */
                if (ksocknal_new_packet (conn, conn->ksnc_rx_nob_left))
                        return (0);     /* come back later */
                goto try_read;          /* try to finish reading slop now */

        case SOCKNAL_RX_BODY_FWD:
                /* payload all received */
                CDEBUG (D_NET, "%p "LPX64"->"LPX64" %d fwd_start (got body)\n",
                        conn, NTOH__u64 (conn->ksnc_hdr.src_nid),
                        NTOH__u64 (conn->ksnc_hdr.dest_nid),
                        conn->ksnc_rx_nob_left);

                /* forward the packet. NB ksocknal_init_fmb() put fmb into
                 * conn->ksnc_cookie */
                fmb = (ksock_fmb_t *)conn->ksnc_cookie;
                kpr_fwd_start (&ksocknal_data.ksnd_router, &fmb->fmb_fwd);

                /* no slop in forwarded packets */
                LASSERT (conn->ksnc_rx_nob_left == 0);

                ksocknal_new_packet (conn, 0);  /* on to next packet */
                return (0);                     /* (later) */

        default:
                break;
        }

        /* Not Reached */
        LBUG ();
        return (-EINVAL);                       /* keep gcc happy */
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
        ksock_conn_t      *conn;
        ksock_tx_t        *tx;
        unsigned long      flags;
        int                rc;
        int                nloops = 0;
        int                id = sched - ksocknal_data.ksnd_schedulers;
        char               name[16];

        snprintf (name, sizeof (name),"ksocknald_%02d", id);
        kportal_daemonize (name);
        kportal_blockallsigs ();

        current->flags |= PF_MEMALLOC;

#if (CONFIG_SMP && CPU_AFFINITY)
        if ((cpu_online_map & (1 << id)) != 0) {
#if 1
                current->cpus_allowed = (1 << id);
#else
                set_cpus_allowed (current, 1<<id);
#endif
        } else {
                CERROR ("Can't set CPU affinity for %s\n", name);
        }
#endif /* CONFIG_SMP && CPU_AFFINITY */
        
        spin_lock_irqsave (&sched->kss_lock, flags);

        while (!ksocknal_data.ksnd_shuttingdown) {
                int did_something = 0;

                /* Ensure I progress everything semi-fairly */

                if (!list_empty (&sched->kss_rx_conns)) {
                        conn = list_entry(sched->kss_rx_conns.next,
                                          ksock_conn_t, ksnc_rx_list);
                        list_del(&conn->ksnc_rx_list);

                        LASSERT(conn->ksnc_rx_scheduled);
                        LASSERT(conn->ksnc_rx_ready);

                        /* clear rx_ready in case receive isn't complete.
                         * Do it BEFORE we call process_recv, since
                         * data_ready can set it any time after we release
                         * kss_lock. */
                        conn->ksnc_rx_ready = 0;
                        spin_unlock_irqrestore(&sched->kss_lock, flags);
                        
                        rc = ksocknal_process_receive(conn);
                        
                        spin_lock_irqsave(&sched->kss_lock, flags);

                        /* I'm the only one that can clear this flag */
                        LASSERT(conn->ksnc_rx_scheduled);

                        /* Did process_receive get everything it wanted? */
                        if (rc == 0)
                                conn->ksnc_rx_ready = 1;
                        
                        if (conn->ksnc_rx_state == SOCKNAL_RX_FMB_SLEEP ||
                            conn->ksnc_rx_state == SOCKNAL_RX_GET_FMB) {
                                /* Conn blocked for a forwarding buffer.
                                 * It will get queued for my attention when
                                 * one becomes available (and it might just
                                 * already have been!).  Meanwhile my ref
                                 * on it stays put. */
                        } else if (conn->ksnc_rx_ready) {
                                /* reschedule for rx */
                                list_add_tail (&conn->ksnc_rx_list,
                                               &sched->kss_rx_conns);
                        } else {
                                conn->ksnc_rx_scheduled = 0;
                                /* drop my ref */
                                ksocknal_put_conn(conn);
                        }

                        did_something = 1;
                }

                if (!list_empty (&sched->kss_tx_conns)) {
                        conn = list_entry(sched->kss_tx_conns.next,
                                          ksock_conn_t, ksnc_tx_list);
                        list_del (&conn->ksnc_tx_list);
                        
                        LASSERT(conn->ksnc_tx_scheduled);
                        LASSERT(conn->ksnc_tx_ready);
                        LASSERT(!list_empty(&conn->ksnc_tx_queue));
                        
                        tx = list_entry(conn->ksnc_tx_queue.next,
                                        ksock_tx_t, tx_list);
                        /* dequeue now so empty list => more to send */
                        list_del(&tx->tx_list);
                        
                        /* Clear tx_ready in case send isn't complete.  Do
                         * it BEFORE we call process_transmit, since
                         * write_space can set it any time after we release
                         * kss_lock. */
                        conn->ksnc_tx_ready = 0;
                        spin_unlock_irqrestore (&sched->kss_lock, flags);
                        
                        rc = ksocknal_process_transmit(conn, tx);
                        
                        spin_lock_irqsave (&sched->kss_lock, flags);

                        if (rc != -EAGAIN) {
                                /* error or everything went: assume more can go */
                                conn->ksnc_tx_ready = 1;
                        } else {
                                 /* back onto HEAD of tx_queue */
                                list_add (&tx->tx_list, &conn->ksnc_tx_queue);
                        }
                        
                        if (conn->ksnc_tx_ready &&
                            !list_empty (&conn->ksnc_tx_queue)) {
                                /* reschedule for tx */
                                list_add_tail (&conn->ksnc_tx_list, 
                                               &sched->kss_tx_conns);
                        } else {
                                conn->ksnc_tx_scheduled = 0;
                                /* drop my ref */
                                ksocknal_put_conn (conn);
                        }
                                
                        did_something = 1;
                }
#if SOCKNAL_ZC
                if (!list_empty (&sched->kss_zctxdone_list)) {
                        ksock_tx_t *tx =
                                list_entry(sched->kss_zctxdone_list.next,
                                           ksock_tx_t, tx_list);
                        did_something = 1;

                        list_del (&tx->tx_list);
                        spin_unlock_irqrestore (&sched->kss_lock, flags);

                        ksocknal_tx_done (tx, 1);

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
        read_lock (&ksocknal_data.ksnd_global_lock);

        conn = sk->sk_user_data;
        if (conn == NULL) {             /* raced with ksocknal_close_sock */
                LASSERT (sk->sk_data_ready != &ksocknal_data_ready);
                sk->sk_data_ready (sk, n);
        } else {
                sched = conn->ksnc_scheduler;

                spin_lock_irqsave (&sched->kss_lock, flags);

                conn->ksnc_rx_ready = 1;

                if (!conn->ksnc_rx_scheduled) {  /* not being progressed */
                        list_add_tail(&conn->ksnc_rx_list,
                                      &sched->kss_rx_conns);
                        conn->ksnc_rx_scheduled = 1;
                        /* extra ref for scheduler */
                        atomic_inc (&conn->ksnc_refcount);

                        wake_up (&sched->kss_waitq);
                }

                spin_unlock_irqrestore (&sched->kss_lock, flags);
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);

        EXIT;
}

void
ksocknal_write_space (struct sock *sk)
{
        unsigned long  flags;
        ksock_conn_t  *conn;
        ksock_sched_t *sched;

        /* interleave correctly with closing sockets... */
        read_lock (&ksocknal_data.ksnd_global_lock);

        conn = sk->sk_user_data;

        CDEBUG(D_NET, "sk %p wspace %d low water %d conn %p%s%s%s\n",
               sk, tcp_wspace(sk), SOCKNAL_TX_LOW_WATER(sk), conn,
               (conn == NULL) ? "" : (conn->ksnc_tx_ready ?
                                      " ready" : " blocked"),
               (conn == NULL) ? "" : (conn->ksnc_tx_scheduled ?
                                      " scheduled" : " idle"),
               (conn == NULL) ? "" : (list_empty (&conn->ksnc_tx_queue) ?
                                      " empty" : " queued"));

        if (conn == NULL) {             /* raced with ksocknal_close_sock */
                LASSERT (sk->sk_write_space != &ksocknal_write_space);
                sk->sk_write_space (sk);

                read_unlock (&ksocknal_data.ksnd_global_lock);
                return;
        }

        if (tcp_wspace(sk) >= SOCKNAL_TX_LOW_WATER(sk)) { /* got enough space */
                clear_bit (SOCK_NOSPACE, &sk->sk_socket->flags);

                sched = conn->ksnc_scheduler;

                spin_lock_irqsave (&sched->kss_lock, flags);

                conn->ksnc_tx_ready = 1;

                if (!conn->ksnc_tx_scheduled && // not being progressed
                    !list_empty(&conn->ksnc_tx_queue)){//packets to send
                        list_add_tail (&conn->ksnc_tx_list,
                                       &sched->kss_tx_conns);
                        conn->ksnc_tx_scheduled = 1;
                        /* extra ref for scheduler */
                        atomic_inc (&conn->ksnc_refcount);

                        wake_up (&sched->kss_waitq);
                }

                spin_unlock_irqrestore (&sched->kss_lock, flags);
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);
}

int
ksocknal_sock_write (struct socket *sock, void *buffer, int nob)
{
        int           rc;
        mm_segment_t  oldmm = get_fs();

        while (nob > 0) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = 0
                };

                set_fs (KERNEL_DS);
                rc = sock_sendmsg (sock, &msg, iov.iov_len);
                set_fs (oldmm);
                
                if (rc < 0)
                        return (rc);

                if (rc == 0) {
                        CERROR ("Unexpected zero rc\n");
                        return (-ECONNABORTED);
                }

                buffer = ((char *)buffer) + rc;
                nob -= rc;
        }
        
        return (0);
}

int
ksocknal_sock_read (struct socket *sock, void *buffer, int nob)
{
        int           rc;
        mm_segment_t  oldmm = get_fs();
        
        while (nob > 0) {
                struct iovec  iov = {
                        .iov_base = buffer,
                        .iov_len  = nob
                };
                struct msghdr msg = {
                        .msg_name       = NULL,
                        .msg_namelen    = 0,
                        .msg_iov        = &iov,
                        .msg_iovlen     = 1,
                        .msg_control    = NULL,
                        .msg_controllen = 0,
                        .msg_flags      = 0
                };

                set_fs (KERNEL_DS);
                rc = sock_recvmsg (sock, &msg, iov.iov_len, 0);
                set_fs (oldmm);
                
                if (rc < 0)
                        return (rc);

                if (rc == 0)
                        return (-ECONNABORTED);

                buffer = ((char *)buffer) + rc;
                nob -= rc;
        }
        
        return (0);
}

int
ksocknal_hello (struct socket *sock, ptl_nid_t *nid, int *type, __u64 *incarnation)
{
        int                 rc;
        ptl_hdr_t           hdr;
        ptl_magicversion_t *hmv = (ptl_magicversion_t *)&hdr.dest_nid;

        LASSERT (sizeof (*hmv) == sizeof (hdr.dest_nid));

        memset (&hdr, 0, sizeof (hdr));
        hmv->magic         = __cpu_to_le32 (PORTALS_PROTO_MAGIC);
        hmv->version_major = __cpu_to_le32 (PORTALS_PROTO_VERSION_MAJOR);
        hmv->version_minor = __cpu_to_le32 (PORTALS_PROTO_VERSION_MINOR);
        
        hdr.src_nid = __cpu_to_le64 (ksocknal_lib.ni.nid);
        hdr.type    = __cpu_to_le32 (PTL_MSG_HELLO);

        hdr.msg.hello.type = __cpu_to_le32 (*type);
        hdr.msg.hello.incarnation = 
                __cpu_to_le64 (ksocknal_data.ksnd_incarnation);

        /* Assume sufficient socket buffering for this message */
        rc = ksocknal_sock_write (sock, &hdr, sizeof (hdr));
        if (rc != 0) {
                CERROR ("Error %d sending HELLO to "LPX64"\n", rc, *nid);
                return (rc);
        }

        rc = ksocknal_sock_read (sock, hmv, sizeof (*hmv));
        if (rc != 0) {
                CERROR ("Error %d reading HELLO from "LPX64"\n", rc, *nid);
                return (rc);
        }
        
        if (hmv->magic != __le32_to_cpu (PORTALS_PROTO_MAGIC)) {
                CERROR ("Bad magic %#08x (%#08x expected) from "LPX64"\n",
                        __cpu_to_le32 (hmv->magic), PORTALS_PROTO_MAGIC, *nid);
                return (-EPROTO);
        }

        if (hmv->version_major != __cpu_to_le16 (PORTALS_PROTO_VERSION_MAJOR) ||
            hmv->version_minor != __cpu_to_le16 (PORTALS_PROTO_VERSION_MINOR)) {
                CERROR ("Incompatible protocol version %d.%d (%d.%d expected)"
                        " from "LPX64"\n",
                        __le16_to_cpu (hmv->version_major),
                        __le16_to_cpu (hmv->version_minor),
                        PORTALS_PROTO_VERSION_MAJOR,
                        PORTALS_PROTO_VERSION_MINOR,
                        *nid);
                return (-EPROTO);
        }

#if (PORTALS_PROTO_VERSION_MAJOR != 0)
# error "This code only understands protocol version 0.x"
#endif
        /* version 0 sends magic/version as the dest_nid of a 'hello' header,
         * so read the rest of it in now... */

        rc = ksocknal_sock_read (sock, hmv + 1, sizeof (hdr) - sizeof (*hmv));
        if (rc != 0) {
                CERROR ("Error %d reading rest of HELLO hdr from "LPX64"\n",
                        rc, *nid);
                return (rc);
        }

        /* ...and check we got what we expected */
        if (hdr.type != __cpu_to_le32 (PTL_MSG_HELLO) ||
            hdr.payload_length != __cpu_to_le32 (0)) {
                CERROR ("Expecting a HELLO hdr with 0 payload,"
                        " but got type %d with %d payload from "LPX64"\n",
                        __le32_to_cpu (hdr.type),
                        __le32_to_cpu (hdr.payload_length), *nid);
                return (-EPROTO);
        }

        if (__le64_to_cpu(hdr.src_nid) == PTL_NID_ANY) {
                CERROR("Expecting a HELLO hdr with a NID, but got PTL_NID_ANY\n");
                return (-EPROTO);
        }

        if (*nid == PTL_NID_ANY) {              /* don't know peer's nid yet */
                *nid = __le64_to_cpu(hdr.src_nid);
        } else if (*nid != __le64_to_cpu (hdr.src_nid)) {
                CERROR ("Connected to nid "LPX64", but expecting "LPX64"\n",
                        __le64_to_cpu (hdr.src_nid), *nid);
                return (-EPROTO);
        }

        if (*type == SOCKNAL_CONN_NONE) {
                /* I've accepted this connection; peer determines type */
                *type = __le32_to_cpu(hdr.msg.hello.type);
                switch (*type) {
                case SOCKNAL_CONN_ANY:
                case SOCKNAL_CONN_CONTROL:
                        break;
                case SOCKNAL_CONN_BULK_IN:
                        *type = SOCKNAL_CONN_BULK_OUT;
                        break;
                case SOCKNAL_CONN_BULK_OUT:
                        *type = SOCKNAL_CONN_BULK_IN;
                        break;
                default:
                        CERROR ("Unexpected type %d from "LPX64"\n", *type, *nid);
                        return (-EPROTO);
                }
        } else if (__le32_to_cpu(hdr.msg.hello.type) != SOCKNAL_CONN_NONE) {
                CERROR ("Mismatched types: me %d "LPX64" %d\n",
                        *type, *nid, __le32_to_cpu(hdr.msg.hello.type));
                return (-EPROTO);
        }

        *incarnation = __le64_to_cpu(hdr.msg.hello.incarnation);

        return (0);
}

int
ksocknal_setup_sock (struct socket *sock)
{
        mm_segment_t    oldmm = get_fs ();
        int             rc;
        int             option;
        struct linger   linger;

        sock->sk->allocation = GFP_NOFS;

        /* Ensure this socket aborts active sends immediately when we close
         * it. */

        linger.l_onoff = 0;
        linger.l_linger = 0;

        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_LINGER,
                              (char *)&linger, sizeof (linger));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set SO_LINGER: %d\n", rc);
                return (rc);
        }

        option = -1;
        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_LINGER2,
                                    (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set SO_LINGER2: %d\n", rc);
                return (rc);
        }

#if SOCKNAL_USE_KEEPALIVES
        /* Keepalives: If 3/4 of the timeout elapses, start probing every
         * second until the timeout elapses. */

        option = (ksocknal_data.ksnd_io_timeout * 3) / 4;
        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_KEEPIDLE,
                                    (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set TCP_KEEPIDLE: %d\n", rc);
                return (rc);
        }
        
        option = 1;
        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_KEEPINTVL,
                                    (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set TCP_KEEPINTVL: %d\n", rc);
                return (rc);
        }
        
        option = ksocknal_data.ksnd_io_timeout / 4;
        set_fs (KERNEL_DS);
        rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_KEEPCNT,
                                    (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set TCP_KEEPINTVL: %d\n", rc);
                return (rc);
        }

        option = 1;
        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_KEEPALIVE, 
                              (char *)&option, sizeof (option));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set SO_KEEPALIVE: %d\n", rc);
                return (rc);
        }
#endif
        return (0);
}

int
ksocknal_connect_peer (ksock_route_t *route, int type)
{
        struct sockaddr_in  peer_addr;
        mm_segment_t        oldmm = get_fs();
        struct timeval      tv;
        int                 fd;
        struct socket      *sock;
        int                 rc;

        rc = sock_create (PF_INET, SOCK_STREAM, 0, &sock);
        if (rc != 0) {
                CERROR ("Can't create autoconnect socket: %d\n", rc);
                return (rc);
        }

        /* Ugh; have to map_fd for compatibility with sockets passed in
         * from userspace.  And we actually need the sock->file refcounting
         * that this gives you :) */

        fd = sock_map_fd (sock);
        if (fd < 0) {
                sock_release (sock);
                CERROR ("sock_map_fd error %d\n", fd);
                return (fd);
        }

        /* NB the fd now owns the ref on sock->file */
        LASSERT (sock->file != NULL);
        LASSERT (file_count(sock->file) == 1);

        /* Set the socket timeouts, so our connection attempt completes in
         * finite time */
        tv.tv_sec = ksocknal_data.ksnd_io_timeout;
        tv.tv_usec = 0;

        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO,
                              (char *)&tv, sizeof (tv));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set send timeout %d: %d\n", 
                        ksocknal_data.ksnd_io_timeout, rc);
                goto out;
        }
        
        set_fs (KERNEL_DS);
        rc = sock_setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO,
                              (char *)&tv, sizeof (tv));
        set_fs (oldmm);
        if (rc != 0) {
                CERROR ("Can't set receive timeout %d: %d\n",
                        ksocknal_data.ksnd_io_timeout, rc);
                goto out;
        }

        if (route->ksnr_nonagel) {
                int  option = 1;
                
                set_fs (KERNEL_DS);
                rc = sock->ops->setsockopt (sock, SOL_TCP, TCP_NODELAY,
                                            (char *)&option, sizeof (option));
                set_fs (oldmm);
                if (rc != 0) {
                        CERROR ("Can't disable nagel: %d\n", rc);
                        goto out;
                }
        }
        
        if (route->ksnr_buffer_size != 0) {
                int option = route->ksnr_buffer_size;
                
                set_fs (KERNEL_DS);
                rc = sock_setsockopt (sock, SOL_SOCKET, SO_SNDBUF,
                                      (char *)&option, sizeof (option));
                set_fs (oldmm);
                if (rc != 0) {
                        CERROR ("Can't set send buffer %d: %d\n",
                                route->ksnr_buffer_size, rc);
                        goto out;
                }

                set_fs (KERNEL_DS);
                rc = sock_setsockopt (sock, SOL_SOCKET, SO_RCVBUF,
                                      (char *)&option, sizeof (option));
                set_fs (oldmm);
                if (rc != 0) {
                        CERROR ("Can't set receive buffer %d: %d\n",
                                route->ksnr_buffer_size, rc);
                        goto out;
                }
        }
        
        memset (&peer_addr, 0, sizeof (peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons (route->ksnr_port);
        peer_addr.sin_addr.s_addr = htonl (route->ksnr_ipaddr);
        
        rc = sock->ops->connect (sock, (struct sockaddr *)&peer_addr, 
                                 sizeof (peer_addr), sock->file->f_flags);
        if (rc != 0) {
                CERROR ("Error %d connecting to "LPX64"\n", rc,
                        route->ksnr_peer->ksnp_nid);
                goto out;
        }
        
        rc = ksocknal_create_conn (route, sock, route->ksnr_irq_affinity, type);
        if (rc == 0) {
                /* Take an extra ref on sock->file to compensate for the
                 * upcoming close which will lose fd's ref on it. */
                get_file (sock->file);
        }

 out:
        sys_close (fd);
        return (rc);
}

void
ksocknal_autoconnect (ksock_route_t *route)
{
        LIST_HEAD        (zombies);
        ksock_tx_t       *tx;
        ksock_peer_t     *peer;
        unsigned long     flags;
        int               rc;
        int               type;
        
        for (;;) {
                for (type = 0; type < SOCKNAL_CONN_NTYPES; type++)
                        if ((route->ksnr_connecting & (1 << type)) != 0)
                                break;
                LASSERT (type < SOCKNAL_CONN_NTYPES);

                rc = ksocknal_connect_peer (route, type);

                if (rc != 0)
                        break;
                
                /* successfully autoconnected: create_conn did the
                 * route/conn binding and scheduled any blocked packets */

                if (route->ksnr_connecting == 0) {
                        /* No more connections required */
                        return;
                }
        }

        /* Connection attempt failed */

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        peer = route->ksnr_peer;
        route->ksnr_connecting = 0;

        /* This is a retry rather than a new connection */
        LASSERT (route->ksnr_retry_interval != 0);
        route->ksnr_timeout = jiffies + route->ksnr_retry_interval;
        route->ksnr_retry_interval = MIN (route->ksnr_retry_interval * 2,
                                          SOCKNAL_MAX_RECONNECT_INTERVAL);

        if (!list_empty (&peer->ksnp_tx_queue) &&
            ksocknal_find_connecting_route_locked (peer) == NULL) {
                LASSERT (list_empty (&peer->ksnp_conns));

                /* None of the connections that the blocked packets are
                 * waiting for have been successful.  Complete them now... */
                do {
                        tx = list_entry (peer->ksnp_tx_queue.next,
                                         ksock_tx_t, tx_list);
                        list_del (&tx->tx_list);
                        list_add_tail (&tx->tx_list, &zombies);
                } while (!list_empty (&peer->ksnp_tx_queue));
        }

        /* make this route least-favourite for re-selection */
        if (!route->ksnr_deleted) {
                list_del(&route->ksnr_list);
                list_add_tail(&route->ksnr_list, &peer->ksnp_routes);
        }
        
        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        while (!list_empty (&zombies)) {
                tx = list_entry (zombies.next, ksock_tx_t, tx_list);
                
                CERROR ("Deleting packet type %d len %d ("LPX64"->"LPX64")\n",
                        NTOH__u32 (tx->tx_hdr->type),
                        NTOH__u32 (tx->tx_hdr->payload_length),
                        NTOH__u64 (tx->tx_hdr->src_nid),
                        NTOH__u64 (tx->tx_hdr->dest_nid));

                list_del (&tx->tx_list);
                /* complete now */
                ksocknal_tx_done (tx, 0);
        }
}

int
ksocknal_autoconnectd (void *arg)
{
        long               id = (long)arg;
        char               name[16];
        unsigned long      flags;
        ksock_route_t     *route;
        int                rc;

        snprintf (name, sizeof (name), "ksocknal_ad%02ld", id);
        kportal_daemonize (name);
        kportal_blockallsigs ();

        spin_lock_irqsave (&ksocknal_data.ksnd_autoconnectd_lock, flags);

        while (!ksocknal_data.ksnd_shuttingdown) {

                if (!list_empty (&ksocknal_data.ksnd_autoconnectd_routes)) {
                        route = list_entry (ksocknal_data.ksnd_autoconnectd_routes.next,
                                            ksock_route_t, ksnr_connect_list);
                        
                        list_del (&route->ksnr_connect_list);
                        spin_unlock_irqrestore (&ksocknal_data.ksnd_autoconnectd_lock, flags);

                        ksocknal_autoconnect (route);
                        ksocknal_put_route (route);

                        spin_lock_irqsave (&ksocknal_data.ksnd_autoconnectd_lock, flags);
                        continue;
                }
                
                spin_unlock_irqrestore (&ksocknal_data.ksnd_autoconnectd_lock, flags);

                rc = wait_event_interruptible (ksocknal_data.ksnd_autoconnectd_waitq,
                                               ksocknal_data.ksnd_shuttingdown ||
                                               !list_empty (&ksocknal_data.ksnd_autoconnectd_routes));

                spin_lock_irqsave (&ksocknal_data.ksnd_autoconnectd_lock, flags);
        }

        spin_unlock_irqrestore (&ksocknal_data.ksnd_autoconnectd_lock, flags);

        ksocknal_thread_fini ();
        return (0);
}

ksock_conn_t *
ksocknal_find_timed_out_conn (ksock_peer_t *peer) 
{
        /* We're called with a shared lock on ksnd_global_lock */
        ksock_conn_t      *conn;
        struct list_head  *ctmp;
        ksock_sched_t     *sched;

        list_for_each (ctmp, &peer->ksnp_conns) {
                conn = list_entry (ctmp, ksock_conn_t, ksnc_list);
                sched = conn->ksnc_scheduler;

                /* Don't need the {get,put}connsock dance to deref ksnc_sock... */
                LASSERT (!conn->ksnc_closing);
                
                if (conn->ksnc_rx_started &&
                    time_after_eq (jiffies, conn->ksnc_rx_deadline)) {
                        /* Timed out incomplete incoming message */
                        atomic_inc (&conn->ksnc_refcount);
                        CERROR ("Timed out RX from "LPX64" %p\n", 
                                peer->ksnp_nid, conn);
                        return (conn);
                }
                
                if ((!list_empty (&conn->ksnc_tx_queue) ||
                     conn->ksnc_sock->sk->sk_wmem_queued != 0) &&
                    time_after_eq (jiffies, conn->ksnc_tx_deadline)) {
                        /* Timed out messages queued for sending, or
                         * messages buffered in the socket's send buffer */
                        atomic_inc (&conn->ksnc_refcount);
                        CERROR ("Timed out TX to "LPX64" %s%d %p\n", 
                                peer->ksnp_nid, 
                                list_empty (&conn->ksnc_tx_queue) ? "" : "Q ",
                                conn->ksnc_sock->sk->sk_wmem_queued, conn);
                        return (conn);
                }
        }

        return (NULL);
}

void
ksocknal_check_peer_timeouts (int idx)
{
        struct list_head *peers = &ksocknal_data.ksnd_peers[idx];
        struct list_head *ptmp;
        ksock_peer_t     *peer;
        ksock_conn_t     *conn;

 again:
        /* NB. We expect to have a look at all the peers and not find any
         * connections to time out, so we just use a shared lock while we
         * take a look... */
        read_lock (&ksocknal_data.ksnd_global_lock);

        list_for_each (ptmp, peers) {
                peer = list_entry (ptmp, ksock_peer_t, ksnp_list);
                conn = ksocknal_find_timed_out_conn (peer);
                
                if (conn != NULL) {
                        read_unlock (&ksocknal_data.ksnd_global_lock);

                        CERROR ("Timeout out conn->"LPX64" ip %x:%d\n",
                                peer->ksnp_nid, conn->ksnc_ipaddr,
                                conn->ksnc_port);
                        ksocknal_close_conn_and_siblings (conn, -ETIMEDOUT);
                        
                        /* NB we won't find this one again, but we can't
                         * just proceed with the next peer, since we dropped
                         * ksnd_global_lock and it might be dead already! */
                        ksocknal_put_conn (conn);
                        goto again;
                }
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);
}

int
ksocknal_reaper (void *arg)
{
        wait_queue_t       wait;
        unsigned long      flags;
        ksock_conn_t      *conn;
        int                timeout;
        int                i;
        int                peer_index = 0;
        unsigned long      deadline = jiffies;
        
        kportal_daemonize ("ksocknal_reaper");
        kportal_blockallsigs ();

        init_waitqueue_entry (&wait, current);

        spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);

        while (!ksocknal_data.ksnd_shuttingdown) {

                if (!list_empty (&ksocknal_data.ksnd_deathrow_conns)) {
                        conn = list_entry (ksocknal_data.ksnd_deathrow_conns.next,
                                           ksock_conn_t, ksnc_list);
                        list_del (&conn->ksnc_list);
                        
                        spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

                        ksocknal_terminate_conn (conn);
                        ksocknal_put_conn (conn);

                        spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);
                        continue;
                }

                if (!list_empty (&ksocknal_data.ksnd_zombie_conns)) {
                        conn = list_entry (ksocknal_data.ksnd_zombie_conns.next,
                                           ksock_conn_t, ksnc_list);
                        list_del (&conn->ksnc_list);
                        
                        spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

                        ksocknal_destroy_conn (conn);

                        spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);
                        continue;
                }
                
                spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

                /* careful with the jiffy wrap... */
                while ((timeout = ((int)deadline - (int)jiffies)) <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = ksocknal_data.ksnd_peer_hash_size;
                        
                        /* Time to check for timeouts on a few more peers: I do
                         * checks every 'p' seconds on a proportion of the peer
                         * table and I need to check every connection 'n' times
                         * within a timeout interval, to ensure I detect a
                         * timeout on any connection within (n+1)/n times the
                         * timeout interval. */

                        if (ksocknal_data.ksnd_io_timeout > n * p)
                                chunk = (chunk * n * p) / 
                                        ksocknal_data.ksnd_io_timeout;
                        if (chunk == 0)
                                chunk = 1;

                        for (i = 0; i < chunk; i++) {
                                ksocknal_check_peer_timeouts (peer_index);
                                peer_index = (peer_index + 1) % 
                                             ksocknal_data.ksnd_peer_hash_size;
                        }

                        deadline += p * HZ;
                }

                add_wait_queue (&ksocknal_data.ksnd_reaper_waitq, &wait);
                set_current_state (TASK_INTERRUPTIBLE);

                if (!ksocknal_data.ksnd_shuttingdown &&
                    list_empty (&ksocknal_data.ksnd_deathrow_conns) &&
                    list_empty (&ksocknal_data.ksnd_zombie_conns))
                        schedule_timeout (timeout);

                set_current_state (TASK_RUNNING);
                remove_wait_queue (&ksocknal_data.ksnd_reaper_waitq, &wait);

                spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);
        }

        spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

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
