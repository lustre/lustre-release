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

#include "socklnd.h"

void
ksocknal_free_ltx (ksock_ltx_t *ltx)
{
        atomic_dec(&ksocknal_data.ksnd_nactive_ltxs);
        PORTAL_FREE(ltx, ltx->ltx_desc_size);
}

int
ksocknal_send_iov (ksock_conn_t *conn, ksock_tx_t *tx)
{ 
        struct iovec  *iov = tx->tx_iov;
        int    nob;
        int    rc;

        LASSERT (tx->tx_niov > 0);

        /* Never touch tx->tx_iov inside ksocknal_lib_send_iov() */
        rc = ksocknal_lib_send_iov(conn, tx);

        if (rc <= 0)                            /* sent nothing? */ 
                return (rc);

        nob = rc; 
        LASSERT (nob <= tx->tx_resid); 
        tx->tx_resid -= nob;

        /* "consume" iov */ 
        do { 
                LASSERT (tx->tx_niov > 0); 

                if (nob < iov->iov_len) { 
                        iov->iov_base = (void *)(((unsigned long)(iov->iov_base)) + nob); 
                        iov->iov_len -= nob; 
                        return (rc); 
                } 

                nob -= iov->iov_len; 
                tx->tx_iov = ++iov; 
                tx->tx_niov--; 
        } while (nob != 0);

        return (rc);
}

int
ksocknal_send_kiov (ksock_conn_t *conn, ksock_tx_t *tx)
{ 
        lnet_kiov_t    *kiov = tx->tx_kiov;
        int     nob;
        int     rc;

        LASSERT (tx->tx_niov == 0); 
        LASSERT (tx->tx_nkiov > 0);

        /* Never touch tx->tx_kiov inside ksocknal_lib_send_kiov() */
        rc = ksocknal_lib_send_kiov(conn, tx);

        if (rc <= 0)                            /* sent nothing? */ 
                return (rc); 
        
        nob = rc; 
        LASSERT (nob <= tx->tx_resid); 
        tx->tx_resid -= nob; 

        /* "consume" kiov */ 
        do { 
                LASSERT(tx->tx_nkiov > 0); 

                if (nob < kiov->kiov_len) { 
                        kiov->kiov_offset += nob; 
                        kiov->kiov_len -= nob; 
                        return rc; 
                } 

                nob -= kiov->kiov_len; 
                tx->tx_kiov = ++kiov; 
                tx->tx_nkiov--; 
        } while (nob != 0);

        return (rc);
}

int
ksocknal_transmit (ksock_conn_t *conn, ksock_tx_t *tx)
{
        int      rc;
        int      bufnob;
        
        if (ksocknal_data.ksnd_stall_tx != 0) {
                cfs_pause(cfs_time_seconds(ksocknal_data.ksnd_stall_tx));
        }

        LASSERT (tx->tx_resid != 0);

        rc = ksocknal_connsock_addref(conn);
        if (rc != 0) {
                LASSERT (conn->ksnc_closing);
                return (-ESHUTDOWN);
        }

        do {
                if (ksocknal_data.ksnd_enomem_tx > 0) {
                        /* testing... */
                        ksocknal_data.ksnd_enomem_tx--;
                        rc = -EAGAIN;
                } else if (tx->tx_niov != 0) {
                        rc = ksocknal_send_iov (conn, tx);
                } else {
                        rc = ksocknal_send_kiov (conn, tx);
                }

                bufnob = SOCK_WMEM_QUEUED(conn->ksnc_sock);
                if (rc > 0)                     /* sent something? */
                        conn->ksnc_tx_bufnob += rc; /* account it */
                
                if (bufnob < conn->ksnc_tx_bufnob) {
                        /* allocated send buffer bytes < computed; infer
                         * something got ACKed */
                        conn->ksnc_tx_deadline = 
                                cfs_time_shift(*ksocknal_tunables.ksnd_timeout);
                        conn->ksnc_peer->ksnp_last_alive = cfs_time_current();
                        conn->ksnc_tx_bufnob = bufnob;
                        mb();
                }

                if (rc <= 0) { /* Didn't write anything? */
                        unsigned long  flags;
                        ksock_sched_t *sched;

                        if (rc == 0) /* some stacks return 0 instead of -EAGAIN */
                                rc = -EAGAIN;

                        if (rc != -EAGAIN)
                                break;

                        /* Check if EAGAIN is due to memory pressure */

                        sched = conn->ksnc_scheduler;
                        spin_lock_irqsave(&sched->kss_lock, flags);
                                
                        if (!SOCK_TEST_NOSPACE(conn->ksnc_sock) &&
                            !conn->ksnc_tx_ready) {
                                /* SOCK_NOSPACE is set when the socket fills
                                 * and cleared in the write_space callback
                                 * (which also sets ksnc_tx_ready).  If
                                 * SOCK_NOSPACE and ksnc_tx_ready are BOTH
                                 * zero, I didn't fill the socket and
                                 * write_space won't reschedule me, so I
                                 * return -ENOMEM to get my caller to retry
                                 * after a timeout */
                                rc = -ENOMEM;
                        }

                        spin_unlock_irqrestore(&sched->kss_lock, flags);
                        break;
                }

                /* socket's wmem_queued now includes 'rc' bytes */
                atomic_sub (rc, &conn->ksnc_tx_nob);
                rc = 0;

        } while (tx->tx_resid != 0);

        ksocknal_connsock_decref(conn);
        return (rc);
}

int
ksocknal_recv_iov (ksock_conn_t *conn)
{ 
        struct iovec *iov = conn->ksnc_rx_iov;
        int     nob;
        int     rc;

        LASSERT (conn->ksnc_rx_niov > 0);

        /* Never touch conn->ksnc_rx_iov or change connection 
         * status inside ksocknal_lib_recv_iov */
        rc = ksocknal_lib_recv_iov(conn); 

        if (rc <= 0) 
                return (rc); 

        /* received something... */ 
        nob = rc; 
        
        conn->ksnc_peer->ksnp_last_alive = cfs_time_current(); 
        conn->ksnc_rx_deadline = 
                cfs_time_shift(*ksocknal_tunables.ksnd_timeout); 
        mb();                           /* order with setting rx_started */ 
        conn->ksnc_rx_started = 1; 
        
        conn->ksnc_rx_nob_wanted -= nob; 
        conn->ksnc_rx_nob_left -= nob;

        do { 
                LASSERT (conn->ksnc_rx_niov > 0); 

                if (nob < iov->iov_len) { 
                        iov->iov_len -= nob; 
                        iov->iov_base = (void *)(((unsigned long)iov->iov_base) + nob); 
                        return (-EAGAIN); 
                } 

                nob -= iov->iov_len; 
                conn->ksnc_rx_iov = ++iov; 
                conn->ksnc_rx_niov--; 
        } while (nob != 0);

        return (rc);
}

int
ksocknal_recv_kiov (ksock_conn_t *conn)
{
        lnet_kiov_t   *kiov = conn->ksnc_rx_kiov;
        int     nob;
        int     rc;
        LASSERT (conn->ksnc_rx_nkiov > 0);

        /* Never touch conn->ksnc_rx_kiov or change connection 
         * status inside ksocknal_lib_recv_iov */
        rc = ksocknal_lib_recv_kiov(conn); 
        
        if (rc <= 0) 
                return (rc); 
        
        /* received something... */ 
        nob = rc; 

        conn->ksnc_peer->ksnp_last_alive = cfs_time_current(); 
        conn->ksnc_rx_deadline = 
                cfs_time_shift(*ksocknal_tunables.ksnd_timeout); 
        mb();                           /* order with setting rx_started */ 
        conn->ksnc_rx_started = 1;

        conn->ksnc_rx_nob_wanted -= nob; 
        conn->ksnc_rx_nob_left -= nob; 
        
        do { 
                LASSERT (conn->ksnc_rx_nkiov > 0); 

                if (nob < kiov->kiov_len) { 
                        kiov->kiov_offset += nob; 
                        kiov->kiov_len -= nob; 
                        return -EAGAIN; 
                } 

                nob -= kiov->kiov_len; 
                conn->ksnc_rx_kiov = ++kiov; 
                conn->ksnc_rx_nkiov--; 
        } while (nob != 0);

        return 1;
}

int
ksocknal_receive (ksock_conn_t *conn) 
{
        /* Return 1 on success, 0 on EOF, < 0 on error.
         * Caller checks ksnc_rx_nob_wanted to determine
         * progress/completion. */
        int     rc;
        ENTRY;
        
        if (ksocknal_data.ksnd_stall_rx != 0) {
                cfs_pause(cfs_time_seconds (ksocknal_data.ksnd_stall_rx));
        }

        rc = ksocknal_connsock_addref(conn);
        if (rc != 0) {
                LASSERT (conn->ksnc_closing);
                return (-ESHUTDOWN);
        }

        for (;;) {
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
                        if ((*ksocknal_tunables.ksnd_eager_ack & conn->ksnc_type) != 0 &&
                            conn->ksnc_rx_state ==  SOCKNAL_RX_BODY) {
                                /* Remind the socket to ack eagerly... */
                                ksocknal_lib_eager_ack(conn);
                        }
                        rc = 1;
                        break;
                }
        }

        ksocknal_connsock_decref(conn);
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
        cfs_waitq_signal (&sched->kss_waitq);

        spin_unlock_irqrestore (&sched->kss_lock, flags);
        EXIT;
}
#endif

void
ksocknal_tx_done (ksock_peer_t *peer, ksock_tx_t *tx, int asynch)
{
        ksock_ltx_t   *ltx;
        ENTRY;

        if (tx->tx_conn != NULL) {
#if SOCKNAL_ZC
                /* zero copy completion isn't always from
                 * process_transmit() so it needs to keep a ref on
                 * tx_conn... */
                if (asynch)
                        ksocknal_conn_decref(tx->tx_conn);
#else
                LASSERT (!asynch);
#endif
        }

        ltx = KSOCK_TX_2_KSOCK_LTX (tx);

        lnet_finalize (peer->ksnp_ni, 
                      ltx->ltx_private, ltx->ltx_cookie,
                      (tx->tx_resid == 0) ? 0 : -EIO);

        ksocknal_free_ltx (ltx);
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
                ksocknal_conn_addref(conn);

                /* ...then drop the initial ref on zccd, so the zero copy
                 * callback can occur */
                zccd_put (&tx->tx_zccd);
                return;
        }
#endif
        /* Any zero-copy-ness (if any) has completed; I can complete the
         * transmit now, avoiding an extra schedule */
        ksocknal_tx_done (tx->tx_conn->ksnc_peer, tx, 0);
}

int
ksocknal_process_transmit (ksock_conn_t *conn, ksock_tx_t *tx)
{
        unsigned long  flags;
        int            rc;
       
        rc = ksocknal_transmit (conn, tx);

        CDEBUG (D_NET, "send(%d) %d\n", tx->tx_resid, rc);

        if (tx->tx_resid == 0) {
                /* Sent everything OK */
                LASSERT (rc == 0);

                ksocknal_tx_launched (tx);
                return (0);
        }

        if (rc == -EAGAIN)
                return (rc);

        if (rc == -ENOMEM) {
                static int counter;

                counter++;   /* exponential backoff warnings */
                if ((counter & (-counter)) == counter)
                        CWARN("%d ENOMEM tx %p (%u allocated)\n",
                              counter, conn, atomic_read(&libcfs_kmemory));

                /* Queue on ksnd_enomem_conns for retry after a timeout */
                spin_lock_irqsave(&ksocknal_data.ksnd_reaper_lock, flags);

                /* enomem list takes over scheduler's ref... */
                LASSERT (conn->ksnc_tx_scheduled);
                list_add_tail(&conn->ksnc_tx_list,
                              &ksocknal_data.ksnd_enomem_conns);
                if (!cfs_time_aftereq(cfs_time_add(cfs_time_current(),
                                                   SOCKNAL_ENOMEM_RETRY),
                                   ksocknal_data.ksnd_reaper_waketime))
                        cfs_waitq_signal (&ksocknal_data.ksnd_reaper_waitq);
                
                spin_unlock_irqrestore(&ksocknal_data.ksnd_reaper_lock, flags);
                return (rc);
        }

        /* Actual error */
        LASSERT (rc < 0);

        if (!conn->ksnc_closing) {
                switch (rc) {
                case -ECONNRESET:
                        LCONSOLE_WARN("Host %u.%u.%u.%u reset our connection "
                                      "while we were sending data; it may have "
                                      "rebooted.\n",
                                      HIPQUAD(conn->ksnc_ipaddr));
                        break;
                default:
                        LCONSOLE_WARN("There was an unexpected network error "
                                      "while writing to %u.%u.%u.%u: %d.\n",
                                      HIPQUAD(conn->ksnc_ipaddr), rc);
                        break;
                }
                CERROR("[%p] Error %d on write to %s"
                       " ip %d.%d.%d.%d:%d\n", conn, rc,
                       libcfs_id2str(conn->ksnc_peer->ksnp_id),
                       HIPQUAD(conn->ksnc_ipaddr),
                       conn->ksnc_port);
        }

        ksocknal_close_conn_and_siblings (conn, rc);
        ksocknal_tx_launched (tx);

        return (rc);
}

void
ksocknal_launch_connection_locked (ksock_route_t *route)
{
        unsigned long     flags;

        /* called holding write lock on ksnd_global_lock */
        LASSERT (!route->ksnr_connecting);
        
        route->ksnr_connecting = 1;             /* scheduling conn for connd */
        ksocknal_route_addref(route);           /* extra ref for connd */
        
        spin_lock_irqsave (&ksocknal_data.ksnd_connd_lock, flags);
        
        list_add_tail (&route->ksnr_connd_list,
                       &ksocknal_data.ksnd_connd_routes);
        cfs_waitq_signal (&ksocknal_data.ksnd_connd_waitq);
        
        spin_unlock_irqrestore (&ksocknal_data.ksnd_connd_lock, flags);
}

ksock_conn_t *
ksocknal_find_conn_locked (ksock_tx_t *tx, ksock_peer_t *peer)
{
        struct list_head *tmp;
        ksock_conn_t     *typed = NULL;
        int               tnob  = 0;
        ksock_conn_t     *fallback = NULL;
        int               fnob     = 0;
        ksock_conn_t     *conn;

        list_for_each (tmp, &peer->ksnp_conns) {
                ksock_conn_t *c = list_entry(tmp, ksock_conn_t, ksnc_list);
#if SOCKNAL_ROUND_ROBIN
                const int     nob = 0;
#else
                int           nob = atomic_read(&c->ksnc_tx_nob) +
                                        SOCK_WMEM_QUEUED(c->ksnc_sock);
#endif
                LASSERT (!c->ksnc_closing);

                if (fallback == NULL || nob < fnob) {
                        fallback = c;
                        fnob     = nob;
                }

                if (!*ksocknal_tunables.ksnd_typed_conns)
                        continue;

                switch (c->ksnc_type) {
                default:
                        CERROR("ksnc_type bad: %u\n", c->ksnc_type);
                        LBUG();
                case SOCKLND_CONN_ANY:
                        break;
                case SOCKLND_CONN_BULK_IN:
                        continue;
                case SOCKLND_CONN_BULK_OUT:
                        if (tx->tx_nob < *ksocknal_tunables.ksnd_min_bulk)
                                continue;
                        break;
                case SOCKLND_CONN_CONTROL:
                        if (tx->tx_nob >= *ksocknal_tunables.ksnd_min_bulk)
                                continue;
                        break;
                }

                if (typed == NULL || nob < tnob) {
                        typed = c;
                        tnob  = nob;
                }
        }

        /* prefer the typed selection */
        conn = (typed != NULL) ? typed : fallback;

#if SOCKNAL_ROUND_ROBIN
        if (conn != NULL) {
                /* round-robin all else being equal */
                list_del (&conn->ksnc_list);
                list_add_tail (&conn->ksnc_list, &peer->ksnp_conns);
        }
#endif
        return conn;
}

void
ksocknal_queue_tx_locked (ksock_tx_t *tx, ksock_conn_t *conn)
{
        unsigned long  flags;
        ksock_sched_t *sched = conn->ksnc_scheduler;

        /* called holding global lock (read or irq-write) and caller may
         * not have dropped this lock between finding conn and calling me,
         * so we don't need the {get,put}connsock dance to deref
         * ksnc_sock... */
        LASSERT(!conn->ksnc_closing);
        LASSERT(tx->tx_resid == tx->tx_nob);
        
        CDEBUG (D_NET, "Sending to %s ip %d.%d.%d.%d:%d\n", 
                libcfs_id2str(conn->ksnc_peer->ksnp_id),
                HIPQUAD(conn->ksnc_ipaddr),
                conn->ksnc_port);

        atomic_add (tx->tx_nob, &conn->ksnc_tx_nob);
        tx->tx_conn = conn;

#if SOCKNAL_ZC
        zccd_init (&tx->tx_zccd, ksocknal_zc_callback);
        /* NB this sets 1 ref on zccd, so the callback can only occur after
         * I've released this ref. */
#endif
        spin_lock_irqsave (&sched->kss_lock, flags);

        if (list_empty(&conn->ksnc_tx_queue) &&
            SOCK_WMEM_QUEUED(conn->ksnc_sock) == 0) {
                /* First packet starts the timeout */
                conn->ksnc_tx_deadline = 
                        cfs_time_shift(*ksocknal_tunables.ksnd_timeout);
                conn->ksnc_tx_bufnob = 0;
                mb();    /* order with adding to tx_queue */
        }

        list_add_tail (&tx->tx_list, &conn->ksnc_tx_queue);
                
        if (conn->ksnc_tx_ready &&      /* able to send */
            !conn->ksnc_tx_scheduled) { /* not scheduled to send */
                /* +1 ref for scheduler */
                ksocknal_conn_addref(conn);
                list_add_tail (&conn->ksnc_tx_list, 
                               &sched->kss_tx_conns);
                conn->ksnc_tx_scheduled = 1;
                cfs_waitq_signal (&sched->kss_waitq);
        }

        spin_unlock_irqrestore (&sched->kss_lock, flags);
}

ksock_route_t *
ksocknal_find_connectable_route_locked (ksock_peer_t *peer)
{
        struct list_head  *tmp;
        ksock_route_t     *route;
        int                bits;
        
        list_for_each (tmp, &peer->ksnp_routes) {
                route = list_entry (tmp, ksock_route_t, ksnr_list);
                bits  = route->ksnr_connected;

                if (*ksocknal_tunables.ksnd_typed_conns) {
                        /* All typed connections established? */
                        if ((bits & KSNR_TYPED_ROUTES) == KSNR_TYPED_ROUTES)
                                continue;
                } else {
                        /* Untyped connection established? */
                        if ((bits & (1 << SOCKLND_CONN_ANY)) != 0)
                                continue;
                }
                
                /* connection being established? */
                if (route->ksnr_connecting)
                        continue;

                /* too soon to retry this guy? */
                if (!(route->ksnr_retry_interval == 0 || /* first attempt */
                      cfs_time_aftereq (cfs_time_current(), 
                                        route->ksnr_timeout)))
                        continue;
                
                return (route);
        }
        
        return (NULL);
}

ksock_route_t *
ksocknal_find_connecting_route_locked (ksock_peer_t *peer)
{
        struct list_head  *tmp;
        ksock_route_t     *route;

        list_for_each (tmp, &peer->ksnp_routes) {
                route = list_entry (tmp, ksock_route_t, ksnr_list);
                
                if (route->ksnr_connecting)
                        return (route);
        }
        
        return (NULL);
}

int
ksocknal_launch_packet (lnet_ni_t *ni, ksock_tx_t *tx, lnet_process_id_t id)
{
        unsigned long     flags;
        ksock_peer_t     *peer;
        ksock_conn_t     *conn;
        ksock_route_t    *route;
        rwlock_t         *g_lock;
        int               retry;
        int               rc;
        
        /* Ensure the frags we've been given EXACTLY match the number of
         * bytes we want to send.  Many TCP/IP stacks disregard any total
         * size parameters passed to them and just look at the frags. 
         *
         * We always expect at least 1 mapped fragment containing the
         * complete portals header. */
        LASSERT (lnet_iov_nob (tx->tx_niov, tx->tx_iov) +
                 lnet_kiov_nob (tx->tx_nkiov, tx->tx_kiov) == tx->tx_nob);
        LASSERT (tx->tx_niov >= 1);
        LASSERT (tx->tx_iov[0].iov_len >= sizeof (lnet_hdr_t));

        CDEBUG (D_NET, "packet %p type %d, nob %d niov %d nkiov %d\n",
                tx, ((lnet_hdr_t *)tx->tx_iov[0].iov_base)->type, 
                tx->tx_nob, tx->tx_niov, tx->tx_nkiov);

        tx->tx_conn = NULL;                     /* only set when assigned a conn */
        tx->tx_resid = tx->tx_nob;
        tx->tx_hdr = (lnet_hdr_t *)tx->tx_iov[0].iov_base;

        g_lock = &ksocknal_data.ksnd_global_lock;
        
        for (retry = 0;; retry = 1) {
#if !SOCKNAL_ROUND_ROBIN
                read_lock (g_lock);
                peer = ksocknal_find_peer_locked(ni, id);
                if (peer != NULL) {
                        if (ksocknal_find_connectable_route_locked(peer) == NULL) {
                                conn = ksocknal_find_conn_locked (tx, peer);
                                if (conn != NULL) {
                                        /* I've got no routes that need to be
                                         * connecting and I do have an actual
                                         * connection... */
                                        ksocknal_queue_tx_locked (tx, conn);
                                        read_unlock (g_lock);
                                        return (0);
                                }
                        }
                }
 
                /* I'll need a write lock... */
                read_unlock (g_lock);
#endif
                write_lock_irqsave(g_lock, flags);

                peer = ksocknal_find_peer_locked(ni, id);
                if (peer != NULL) 
                        break;
                
                write_unlock_irqrestore(g_lock, flags);

                if ((id.pid & LNET_PID_USERFLAG) != 0) {
                        CERROR("Refusing to create a connection to "
                               "userspace process %s\n", libcfs_id2str(id));
                        return -EHOSTUNREACH;
                }
                
                if (retry) {
                        CERROR("Can't find peer %s\n", libcfs_id2str(id));
                        return -EHOSTUNREACH;
                }
                
                rc = ksocknal_add_peer(ni, id, 
                                       PTL_NIDADDR(id.nid),
                                       lnet_acceptor_port());
                if (rc != 0) {
                        CERROR("Can't add peer %s: %d\n",
                               libcfs_id2str(id), rc);
                        return rc;
                }
        }

        for (;;) {
                /* launch any/all connections that need it */
                route = ksocknal_find_connectable_route_locked (peer);
                if (route == NULL)
                        break;

                ksocknal_launch_connection_locked (route);
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

        CERROR("Peer entry with no routes: %s\n", libcfs_id2str(id));
        return (-EHOSTUNREACH);
}

int
ksocknal_send(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg)
{
        lnet_hdr_t       *hdr = &lntmsg->msg_hdr; 
        int               type = lntmsg->msg_type; 
        lnet_process_id_t target = lntmsg->msg_target;
        unsigned int      payload_niov = lntmsg->msg_niov; 
        struct iovec     *payload_iov = lntmsg->msg_iov; 
        lnet_kiov_t      *payload_kiov = lntmsg->msg_kiov;
        unsigned int      payload_offset = lntmsg->msg_offset;
        unsigned int      payload_nob = lntmsg->msg_len;
        ksock_ltx_t      *ltx;
        int               desc_size;
        int               rc;

        /* NB 'private' is different depending on what we're sending.
         * Just ignore it... */

        CDEBUG(D_NET, "sending %u bytes in %d frags to %s\n",
               payload_nob, payload_niov, libcfs_id2str(target));

        LASSERT (payload_nob == 0 || payload_niov > 0);
        LASSERT (payload_niov <= PTL_MD_MAX_IOV);

        /* It must be OK to kmap() if required */
        LASSERT (payload_kiov == NULL || !in_interrupt ());
        /* payload is either all vaddrs or all pages */
        LASSERT (!(payload_kiov != NULL && payload_iov != NULL));
        
        if (payload_iov != NULL)
                desc_size = offsetof(ksock_ltx_t, ltx_iov[1 + payload_niov]);
        else
                desc_size = offsetof(ksock_ltx_t, ltx_kiov[payload_niov]);
        
        if (in_interrupt() ||
            type == LNET_MSG_ACK ||
            type == LNET_MSG_REPLY) {
                /* Can't block if in interrupt or responding to an incoming
                 * message */
                PORTAL_ALLOC_ATOMIC(ltx, desc_size);
        } else {
                PORTAL_ALLOC(ltx, desc_size);
        }
        
        if (ltx == NULL) {
                CERROR("Can't allocate tx desc type %d size %d %s\n",
                       type, desc_size, in_interrupt() ? "(intr)" : "");
                return (-ENOMEM);
        }

        atomic_inc(&ksocknal_data.ksnd_nactive_ltxs);

        ltx->ltx_desc_size = desc_size;
        
        /* We always have 1 mapped frag for the header */
        ltx->ltx_tx.tx_iov = ltx->ltx_iov;
        ltx->ltx_iov[0].iov_base = &ltx->ltx_hdr;
        ltx->ltx_iov[0].iov_len = sizeof(*hdr);
        ltx->ltx_hdr = *hdr;
        
        ltx->ltx_private = private;
        ltx->ltx_cookie = lntmsg;
        
        ltx->ltx_tx.tx_nob = sizeof (*hdr) + payload_nob;

        if (payload_iov != NULL) {
                /* payload is all mapped */
                ltx->ltx_tx.tx_kiov  = NULL;
                ltx->ltx_tx.tx_nkiov = 0;

                ltx->ltx_tx.tx_niov = 
                        1 + lnet_extract_iov(payload_niov, &ltx->ltx_iov[1],
                                            payload_niov, payload_iov,
                                            payload_offset, payload_nob);
        } else {
                /* payload is all pages */
                ltx->ltx_tx.tx_niov = 1;

                ltx->ltx_tx.tx_kiov = ltx->ltx_kiov;
                ltx->ltx_tx.tx_nkiov =
                        lnet_extract_kiov(payload_niov, ltx->ltx_kiov,
                                         payload_niov, payload_kiov,
                                         payload_offset, payload_nob);
        }

        rc = ksocknal_launch_packet(ni, &ltx->ltx_tx, target);
        if (rc == 0)
                return (0);
        
        ksocknal_free_ltx(ltx);
        return (-EIO);
}

int
ksocknal_thread_start (int (*fn)(void *arg), void *arg)
{
        long          pid = cfs_kernel_thread (fn, arg, 0);
        unsigned long flags;

        if (pid < 0)
                return ((int)pid);

        write_lock_irqsave(&ksocknal_data.ksnd_global_lock, flags);
        ksocknal_data.ksnd_nthreads++;
        write_unlock_irqrestore(&ksocknal_data.ksnd_global_lock, flags);
        return (0);
}

void
ksocknal_thread_fini (void)
{
        unsigned long flags;

        write_lock_irqsave(&ksocknal_data.ksnd_global_lock, flags);
        ksocknal_data.ksnd_nthreads--;
        write_unlock_irqrestore(&ksocknal_data.ksnd_global_lock, flags);
}

int
ksocknal_new_packet (ksock_conn_t *conn, int nob_to_skip)
{
        static char ksocknal_slop_buffer[4096];

        int            nob;
        unsigned int   niov;
        int            skipped;

        if (nob_to_skip == 0) {         /* right at next packet boundary now */
                conn->ksnc_rx_started = 0;
                mb ();                          /* racing with timeout thread */
                
                conn->ksnc_rx_state = SOCKNAL_RX_HEADER;
                conn->ksnc_rx_nob_wanted = sizeof (lnet_hdr_t);
                conn->ksnc_rx_nob_left = sizeof (lnet_hdr_t);

                conn->ksnc_rx_iov = (struct iovec *)&conn->ksnc_rx_iov_space;
                conn->ksnc_rx_iov[0].iov_base = (char *)&conn->ksnc_hdr;
                conn->ksnc_rx_iov[0].iov_len  = sizeof (lnet_hdr_t);
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
        int           rc;
        
        LASSERT (atomic_read(&conn->ksnc_conn_refcount) > 0);

        /* NB: sched lock NOT held */
        LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_HEADER ||
                 conn->ksnc_rx_state == SOCKNAL_RX_BODY ||
                 conn->ksnc_rx_state == SOCKNAL_RX_SLOP);
 again:
        if (conn->ksnc_rx_nob_wanted != 0) {
                rc = ksocknal_receive(conn);

                if (rc <= 0) {
                        LASSERT (rc != -EAGAIN);

                        if (rc == 0)
                                CDEBUG (D_NET, "[%p] EOF from %s"
                                        " ip %d.%d.%d.%d:%d\n", conn, 
                                        libcfs_id2str(conn->ksnc_peer->ksnp_id),
                                        HIPQUAD(conn->ksnc_ipaddr),
                                        conn->ksnc_port);
                        else if (!conn->ksnc_closing)
                                CERROR ("[%p] Error %d on read from %s"
                                        " ip %d.%d.%d.%d:%d\n",
                                        conn, rc, 
                                        libcfs_id2str(conn->ksnc_peer->ksnp_id),
                                        HIPQUAD(conn->ksnc_ipaddr),
                                        conn->ksnc_port);

                        ksocknal_close_conn_and_siblings (conn, rc);
                        return (rc == 0 ? -ESHUTDOWN : rc);
                }
                
                if (conn->ksnc_rx_nob_wanted != 0) {
                        /* short read */
                        return (-EAGAIN);
                }
        }
        
        switch (conn->ksnc_rx_state) {
        case SOCKNAL_RX_HEADER:
                if ((conn->ksnc_peer->ksnp_id.pid & LNET_PID_USERFLAG) != 0) { 
                        /* Userspace peer */
                        lnet_process_id_t *id = &conn->ksnc_peer->ksnp_id;
                        
                        /* Substitute process ID assigned at connection time */
                        conn->ksnc_hdr.src_pid = cpu_to_le32(id->pid);
                        conn->ksnc_hdr.src_nid = cpu_to_le64(id->nid);
                }

                conn->ksnc_rx_state = SOCKNAL_RX_PARSE;
                ksocknal_conn_addref(conn);     /* ++ref while parsing */
                
                rc = lnet_parse(conn->ksnc_peer->ksnp_ni, &conn->ksnc_hdr, conn);
                if (rc < 0) {
                        /* I just received garbage: give up on this conn */
                        ksocknal_new_packet(conn, 0);
                        ksocknal_close_conn_and_siblings (conn, rc);
                        ksocknal_conn_decref(conn);
                        return (-EPROTO);
                }

                /* I'm racing with ksocknal_recv() */
                LASSERT (conn->ksnc_rx_state == SOCKNAL_RX_PARSE ||
                         conn->ksnc_rx_state == SOCKNAL_RX_BODY);
                
                if (conn->ksnc_rx_state != SOCKNAL_RX_BODY)
                        return 0;
                
                /* ksocknal_recv() got called */
                goto again;

        case SOCKNAL_RX_BODY:
                /* payload all received */
                lnet_finalize(conn->ksnc_peer->ksnp_ni, NULL, conn->ksnc_cookie, 0);
                /* Fall through */

        case SOCKNAL_RX_SLOP:
                /* starting new packet? */
                if (ksocknal_new_packet (conn, conn->ksnc_rx_nob_left))
                        return 0;       /* come back later */
                goto again;             /* try to finish reading slop now */

        default:
                break;
        }

        /* Not Reached */
        LBUG ();
        return (-EINVAL);                       /* keep gcc happy */
}

int
ksocknal_recv (lnet_ni_t *ni, void *private, lnet_msg_t *msg, int delayed,
               unsigned int niov, struct iovec *iov, lnet_kiov_t *kiov,
               unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        ksock_conn_t  *conn = (ksock_conn_t *)private;
        ksock_sched_t *sched = conn->ksnc_scheduler;
        unsigned int   flags;

        LASSERT (mlen <= rlen);
        LASSERT (niov <= PTL_MD_MAX_IOV);
        
        conn->ksnc_cookie = msg;
        conn->ksnc_rx_nob_wanted = mlen;
        conn->ksnc_rx_nob_left   = rlen;

        if (mlen == 0 || iov != NULL) {
                conn->ksnc_rx_nkiov = 0;
                conn->ksnc_rx_kiov = NULL;
                conn->ksnc_rx_iov = conn->ksnc_rx_iov_space.iov;
                conn->ksnc_rx_niov =
                        lnet_extract_iov(PTL_MD_MAX_IOV, conn->ksnc_rx_iov,
                                         niov, iov, offset, mlen);
        } else {
                conn->ksnc_rx_niov = 0;
                conn->ksnc_rx_iov  = NULL;
                conn->ksnc_rx_kiov = conn->ksnc_rx_iov_space.kiov;
                conn->ksnc_rx_nkiov = 
                        lnet_extract_kiov(PTL_MD_MAX_IOV, conn->ksnc_rx_kiov,
                                          niov, kiov, offset, mlen);
        }
        
        LASSERT (mlen == 
                 lnet_iov_nob (conn->ksnc_rx_niov, conn->ksnc_rx_iov) +
                 lnet_kiov_nob (conn->ksnc_rx_nkiov, conn->ksnc_rx_kiov));

        LASSERT (conn->ksnc_rx_scheduled);

        spin_lock_irqsave(&sched->kss_lock, flags);

        switch (conn->ksnc_rx_state) {
        case SOCKNAL_RX_PARSE_WAIT:
                list_add_tail(&conn->ksnc_rx_list, &sched->kss_rx_conns);
                cfs_waitq_signal (&sched->kss_waitq);
                LASSERT (conn->ksnc_rx_ready);
                break;
                
        case SOCKNAL_RX_PARSE:
                /* scheduler hasn't noticed I'm parsing yet */
                break;
        }

        conn->ksnc_rx_state = SOCKNAL_RX_BODY;
        
        spin_unlock_irqrestore(&sched->kss_lock, flags);
        ksocknal_conn_decref(conn);
        return (0);
}

static inline int
ksocknal_sched_cansleep(ksock_sched_t *sched)
{
        unsigned long flags;
        int           rc;

        spin_lock_irqsave(&sched->kss_lock, flags);

        rc = (!ksocknal_data.ksnd_shuttingdown &&
#if SOCKNAL_ZC
              list_empty(&sched->kss_zctxdone_list) &&
#endif
              list_empty(&sched->kss_rx_conns) &&
              list_empty(&sched->kss_tx_conns));
        
        spin_unlock_irqrestore(&sched->kss_lock, flags);
        return (rc);
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

        snprintf (name, sizeof (name),"socknal_sd%02d", id);
        libcfs_daemonize (name);
        libcfs_blockallsigs ();

#if (CONFIG_SMP && CPU_AFFINITY)
        id = ksocknal_sched2cpu(id);
        if (cpu_online(id)) {
                cpumask_t m;
                cpu_set(id, m);
                set_cpus_allowed(current, m);
        } else {
                CERROR ("Can't set CPU affinity for %s to %d\n", name, id);
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

                        if (conn->ksnc_rx_state == SOCKNAL_RX_PARSE) {
                                /* Conn blocked waiting for ksocknal_recv()
                                 * I change its state (under lock) to signal
                                 * it can be rescheduled */
                                conn->ksnc_rx_state = SOCKNAL_RX_PARSE_WAIT;
                        } else if (conn->ksnc_rx_ready) {
                                /* reschedule for rx */
                                list_add_tail (&conn->ksnc_rx_list,
                                               &sched->kss_rx_conns);
                        } else {
                                conn->ksnc_rx_scheduled = 0;
                                /* drop my ref */
                                ksocknal_conn_decref(conn);
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

                        if (rc == -ENOMEM || rc == -EAGAIN) {
                                /* Incomplete send: replace tx on HEAD of tx_queue */
                                list_add (&tx->tx_list, &conn->ksnc_tx_queue);
                        } else {
                                /* Complete send; assume space for more */
                                conn->ksnc_tx_ready = 1;
                        }

                        if (rc == -ENOMEM) {
                                /* Do nothing; after a short timeout, this
                                 * conn will be reposted on kss_tx_conns. */
                        } else if (conn->ksnc_tx_ready &&
                                   !list_empty (&conn->ksnc_tx_queue)) {
                                /* reschedule for tx */
                                list_add_tail (&conn->ksnc_tx_list, 
                                               &sched->kss_tx_conns);
                        } else {
                                conn->ksnc_tx_scheduled = 0;
                                /* drop my ref */
                                ksocknal_conn_decref(conn);
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

                        ksocknal_tx_done (tx->tx_conn->ksnc_peer, tx, 1);

                        spin_lock_irqsave (&sched->kss_lock, flags);
                }
#endif
                if (!did_something ||           /* nothing to do */
                    ++nloops == SOCKNAL_RESCHED) { /* hogging CPU? */
                        spin_unlock_irqrestore (&sched->kss_lock, flags);

                        nloops = 0;

                        if (!did_something) {   /* wait for something to do */
                                rc = wait_event_interruptible (sched->kss_waitq,
                                                               !ksocknal_sched_cansleep(sched));
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

/*
 * Add connection to kss_rx_conns of scheduler
 * and wakeup the scheduler.
 */
void ksocknal_read_callback (ksock_conn_t *conn)
{
        ksock_sched_t *sched; 
        unsigned long  flags;
        ENTRY;

        sched = conn->ksnc_scheduler; 

        spin_lock_irqsave (&sched->kss_lock, flags); 

        conn->ksnc_rx_ready = 1; 

        if (!conn->ksnc_rx_scheduled) {  /* not being progressed */ 
                list_add_tail(&conn->ksnc_rx_list, 
                              &sched->kss_rx_conns); 
                conn->ksnc_rx_scheduled = 1; 
                /* extra ref for scheduler */ 
                ksocknal_conn_addref(conn);

                cfs_waitq_signal (&sched->kss_waitq); 
        } 
        spin_unlock_irqrestore (&sched->kss_lock, flags);

        EXIT;
} 

/*
 * Add connection to kss_tx_conns of scheduler
 * and wakeup the scheduler.
 */
void ksocknal_write_callback (ksock_conn_t *conn)
{ 
        ksock_sched_t *sched; 
        unsigned long  flags;
        ENTRY;
        
        sched = conn->ksnc_scheduler; 

        spin_lock_irqsave (&sched->kss_lock, flags); 

        conn->ksnc_tx_ready = 1; 

        if (!conn->ksnc_tx_scheduled && // not being progressed 
            !list_empty(&conn->ksnc_tx_queue)){//packets to send 
                list_add_tail (&conn->ksnc_tx_list, 
                               &sched->kss_tx_conns); 
                conn->ksnc_tx_scheduled = 1; 
                /* extra ref for scheduler */ 
                ksocknal_conn_addref(conn); 

                cfs_waitq_signal (&sched->kss_waitq); 
        } 

        spin_unlock_irqrestore (&sched->kss_lock, flags);

        EXIT;
}

int
ksocknal_send_hello (lnet_ni_t *ni, ksock_conn_t *conn, lnet_nid_t peer_nid,
                     __u32 *ipaddrs, int nipaddrs)
{
        /* CAVEAT EMPTOR: this byte flips 'ipaddrs' */
        ksock_net_t         *net = (ksock_net_t *)ni->ni_data;
        struct socket       *sock = conn->ksnc_sock;
        lnet_hdr_t           hdr;
        lnet_magicversion_t *hmv = (lnet_magicversion_t *)&hdr.dest_nid;
        int                  i;
        int                  rc;
        lnet_nid_t           srcnid;

        LASSERT (conn->ksnc_type != SOCKLND_CONN_NONE);
        LASSERT (0 <= nipaddrs && nipaddrs <= LNET_MAX_INTERFACES);

        /* No need for getconnsock/putconnsock */
        LASSERT (!conn->ksnc_closing);

        LASSERT (sizeof (*hmv) == sizeof (hdr.dest_nid));
        hmv->magic         = cpu_to_le32 (LNET_PROTO_TCP_MAGIC);
        hmv->version_major = cpu_to_le16 (LNET_PROTO_TCP_VERSION_MAJOR);
        hmv->version_minor = cpu_to_le16 (LNET_PROTO_TCP_VERSION_MINOR);

        srcnid = lnet_ptlcompat_srcnid(ni->ni_nid, peer_nid);
        
        hdr.src_nid        = cpu_to_le64 (srcnid);
        hdr.src_pid        = cpu_to_le64 (the_lnet.ln_pid);
        hdr.type           = cpu_to_le32 (LNET_MSG_HELLO);
        hdr.payload_length = cpu_to_le32 (nipaddrs * sizeof(*ipaddrs));

        hdr.msg.hello.type = cpu_to_le32 (conn->ksnc_type);
        hdr.msg.hello.incarnation = cpu_to_le64 (net->ksnn_incarnation);

        for (i = 0; i < nipaddrs; i++) {
                ipaddrs[i] = __cpu_to_le32 (ipaddrs[i]);
        }

        /* socket buffer should have been set large enough not to block
         * (timeout == 0) */
        rc = libcfs_sock_write(sock, &hdr, sizeof(hdr), 0);
        if (rc != 0) {
                CERROR ("Error %d sending HELLO hdr to %u.%u.%u.%u/%d\n",
                        rc, HIPQUAD(conn->ksnc_ipaddr), conn->ksnc_port);
                return (rc);
        }
        
        if (nipaddrs == 0)
                return (0);
        
        rc = libcfs_sock_write(sock, ipaddrs, nipaddrs * sizeof(*ipaddrs), 0);
        if (rc != 0)
                CERROR ("Error %d sending HELLO payload (%d)"
                        " to %u.%u.%u.%u/%d\n", rc, nipaddrs, 
                        HIPQUAD(conn->ksnc_ipaddr), conn->ksnc_port);
        return (rc);
}

int
ksocknal_invert_type(int type)
{
        switch (type)
        {
        case SOCKLND_CONN_ANY:
        case SOCKLND_CONN_CONTROL:
                return (type);
        case SOCKLND_CONN_BULK_IN:
                return SOCKLND_CONN_BULK_OUT;
        case SOCKLND_CONN_BULK_OUT:
                return SOCKLND_CONN_BULK_IN;
        default:
                return (SOCKLND_CONN_NONE);
        }
}

int
ksocknal_recv_hello (lnet_ni_t *ni, ksock_conn_t *conn, 
                     lnet_process_id_t *peerid, 
                     __u64 *incarnation, __u32 *ipaddrs)
{
        struct socket       *sock = conn->ksnc_sock;
        int                  active;
        int                  timeout;
        int                  rc;
        int                  nips;
        int                  i;
        int                  type;
        lnet_hdr_t           hdr;
        lnet_process_id_t    recv_id;
        lnet_magicversion_t *hmv;

        active = (peerid->nid != LNET_NID_ANY);
        timeout = active ? *ksocknal_tunables.ksnd_timeout :
                            lnet_acceptor_timeout();

        hmv = (lnet_magicversion_t *)&hdr.dest_nid;
        LASSERT (sizeof (*hmv) == sizeof (hdr.dest_nid));

        rc = libcfs_sock_read(sock, &hmv->magic, sizeof (hmv->magic), timeout);
        if (rc != 0) {
                CERROR ("Error %d reading HELLO from %u.%u.%u.%u\n",
                        rc, HIPQUAD(conn->ksnc_ipaddr));
                return (rc);
        }

        if (!active && 
            hmv->magic != le32_to_cpu (LNET_PROTO_TCP_MAGIC)) {
                /* Is this a generic acceptor connection request? */
                rc = lnet_accept(ni, sock, hmv->magic);
                if (rc != 0)
                        return -EPROTO;

                /* Yes it is! Start over again now I've skipping the generic
                 * request */
                rc = libcfs_sock_read(sock, &hmv->magic, 
                                      sizeof (hmv->magic), timeout);
                if (rc != 0) {
                        CERROR ("Error %d reading HELLO from %u.%u.%u.%u\n",
                                rc, HIPQUAD(conn->ksnc_ipaddr));
                        return (rc);
                }
        }
        
        if (hmv->magic != le32_to_cpu (LNET_PROTO_TCP_MAGIC)) {
                CERROR ("Bad magic %#08x (%#08x expected) from %u.%u.%u.%u\n",
                        __cpu_to_le32 (hmv->magic), LNET_PROTO_TCP_MAGIC,
                        HIPQUAD(conn->ksnc_ipaddr));
                return (-EPROTO);
        }

        rc = libcfs_sock_read(sock, &hmv->magic + 1,
                              sizeof(*hmv) - sizeof(hmv->magic), timeout);
        if (rc != 0) {
                CERROR ("Error %d reading HELLO from %u.%u.%u.%u\n",
                        rc, HIPQUAD(conn->ksnc_ipaddr));
                return (rc);
        }
        
        if (hmv->version_major != cpu_to_le16 (LNET_PROTO_TCP_VERSION_MAJOR) ||
            hmv->version_minor != cpu_to_le16 (LNET_PROTO_TCP_VERSION_MINOR)) {
                CERROR ("Incompatible protocol version %d.%d (%d.%d expected)"
                        " from %u.%u.%u.%u\n",
                        le16_to_cpu (hmv->version_major),
                        le16_to_cpu (hmv->version_minor),
                        LNET_PROTO_TCP_VERSION_MAJOR,
                        LNET_PROTO_TCP_VERSION_MINOR,
                        HIPQUAD(conn->ksnc_ipaddr));
                return (-EPROTO);
        }

#if (LNET_PROTO_TCP_VERSION_MAJOR != 1)
# error "This code only understands protocol version 1.x"
#endif
        /* version 1 sends magic/version as the dest_nid of a 'hello'
         * header, followed by payload full of interface IP addresses.
         * Read the rest of it in now... */

        rc = libcfs_sock_read(sock, hmv + 1, sizeof (hdr) - sizeof (*hmv), 
                              timeout);
        if (rc != 0) {
                CERROR ("Error %d reading rest of HELLO hdr from %u.%u.%u.%u\n",
                        rc, HIPQUAD(conn->ksnc_ipaddr));
                return (rc);
        }

        /* ...and check we got what we expected */
        if (hdr.type != cpu_to_le32 (LNET_MSG_HELLO)) {
                CERROR ("Expecting a HELLO hdr,"
                        " but got type %d from %u.%u.%u.%u\n",
                        le32_to_cpu (hdr.type),
                        HIPQUAD(conn->ksnc_ipaddr));
                return (-EPROTO);
        }

        if (le64_to_cpu(hdr.src_nid) == LNET_NID_ANY) {
                CERROR("Expecting a HELLO hdr with a NID, but got LNET_NID_ANY"
                       "from %u.%u.%u.%u\n", HIPQUAD(conn->ksnc_ipaddr));
                return (-EPROTO);
        }

        if (conn->ksnc_port > LNET_ACCEPTOR_MAX_RESERVED_PORT) {          
                /* Userspace NAL assigns peer process ID from socket */
                recv_id.pid = conn->ksnc_port | LNET_PID_USERFLAG;
                recv_id.nid = PTL_MKNID(PTL_NIDNET(ni->ni_nid), conn->ksnc_ipaddr);
        } else {
                recv_id.nid = le64_to_cpu(hdr.src_nid);

                if (the_lnet.ln_ptlcompat > 1 && /* portals peers may exist */
                    PTL_NIDNET(recv_id.nid) == 0) /* this is one */
                        recv_id.pid = the_lnet.ln_pid; /* give it a sensible pid */
                else
                        recv_id.pid = le32_to_cpu(hdr.src_pid);

        }
        
        if (!active) {                          /* don't know peer's nid yet */
                *peerid = recv_id;
        } else if (peerid->pid != recv_id.pid ||
                   !lnet_ptlcompat_matchnid(peerid->nid, recv_id.nid)) {
                LCONSOLE_ERROR("Connected successfully to %s on host "
                               "%u.%u.%u.%u, but they claimed they were "
                               "%s; please check your Lustre "
                               "configuration.\n",
                               libcfs_id2str(*peerid),
                               HIPQUAD(conn->ksnc_ipaddr),
                               libcfs_id2str(recv_id));
                               
                CERROR ("Connected to %s ip %u.%u.%u.%u "
                        "but expecting %s\n",
                        libcfs_id2str(recv_id),
                        HIPQUAD(conn->ksnc_ipaddr),
                        libcfs_id2str(*peerid));
                return (-EPROTO);
        }

        type = __le32_to_cpu(hdr.msg.hello.type);

        if (conn->ksnc_type == SOCKLND_CONN_NONE) {
                /* I've accepted this connection; peer determines type */
                conn->ksnc_type = ksocknal_invert_type(type);
                if (conn->ksnc_type == SOCKLND_CONN_NONE) {
                        CERROR ("Unexpected type %d from %s ip %u.%u.%u.%u\n",
                                type, libcfs_id2str(*peerid), 
                                HIPQUAD(conn->ksnc_ipaddr));
                        return (-EPROTO);
                }
        } else if (ksocknal_invert_type(type) != conn->ksnc_type) {
                CERROR ("Mismatched types: me %d, %s ip %u.%u.%u.%u %d\n",
                        conn->ksnc_type, libcfs_id2str(*peerid), 
                        HIPQUAD(conn->ksnc_ipaddr),
                        le32_to_cpu(hdr.msg.hello.type));
                return (-EPROTO);
        }

        *incarnation = le64_to_cpu(hdr.msg.hello.incarnation);

        nips = __le32_to_cpu (hdr.payload_length) / sizeof (__u32);

        if (nips > LNET_MAX_INTERFACES ||
            nips * sizeof(__u32) != __le32_to_cpu (hdr.payload_length)) {
                CERROR("Bad payload length %d from %s ip %u.%u.%u.%u\n",
                       __le32_to_cpu (hdr.payload_length),
                       libcfs_id2str(*peerid), HIPQUAD(conn->ksnc_ipaddr));
        }

        if (nips == 0)
                return (0);
        
        rc = libcfs_sock_read(sock, ipaddrs, nips * sizeof(*ipaddrs), timeout);
        if (rc != 0) {
                CERROR ("Error %d reading IPs from %s ip %u.%u.%u.%u\n",
                        rc, libcfs_id2str(*peerid), HIPQUAD(conn->ksnc_ipaddr));
                return (rc);
        }

        for (i = 0; i < nips; i++) {
                ipaddrs[i] = __le32_to_cpu(ipaddrs[i]);
                
                if (ipaddrs[i] == 0) {
                        CERROR("Zero IP[%d] from %s ip %u.%u.%u.%u\n",
                               i, libcfs_id2str(*peerid),
                               HIPQUAD(conn->ksnc_ipaddr));
                        return (-EPROTO);
                }
        }

        return (nips);
}

void
ksocknal_connect (ksock_route_t *route)
{
        CFS_LIST_HEAD    (zombies);
        ksock_tx_t       *tx;
        ksock_peer_t     *peer = route->ksnr_peer;
        unsigned long     flags;
        int               type;
        struct socket    *sock;
        int               rc = 0;

        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        for (;;) {
                if (!*ksocknal_tunables.ksnd_typed_conns) {
                        if ((route->ksnr_connected & (1<<SOCKLND_CONN_ANY)) == 0)
                                type = SOCKLND_CONN_ANY;
                        else
                                break;  /* got connected while route queued */
                } else {
                        if ((route->ksnr_connected & (1<<SOCKLND_CONN_CONTROL)) == 0)
                                type = SOCKLND_CONN_CONTROL;
                        else if ((route->ksnr_connected & (1<<SOCKLND_CONN_BULK_IN)) == 0)
                                type = SOCKLND_CONN_BULK_IN;
                        else if ((route->ksnr_connected & (1<<SOCKLND_CONN_BULK_OUT)) == 0)
                                type = SOCKLND_CONN_BULK_OUT;
                        else
                                break;  /* got connected while route queued */
                }

                write_unlock_irqrestore(&ksocknal_data.ksnd_global_lock, flags);

                rc = lnet_connect(&sock, peer->ksnp_id.nid,
                                 route->ksnr_myipaddr, 
                                 route->ksnr_ipaddr, route->ksnr_port);
                if (rc != 0)
                        goto failed;

                rc = ksocknal_create_conn(peer->ksnp_ni, route, sock, type);
                if (rc != 0) {
                        lnet_connect_console_error(rc, peer->ksnp_id.nid,
                                                  route->ksnr_ipaddr, 
                                                  route->ksnr_port);
                        goto failed;
                }
                
                write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);
        }

        LASSERT (route->ksnr_connecting);
        route->ksnr_connecting = 0;
        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);
        return;

 failed:
        write_lock_irqsave (&ksocknal_data.ksnd_global_lock, flags);

        LASSERT (route->ksnr_connecting);
        route->ksnr_connecting = 0;

        /* This is a retry rather than a new connection */
        route->ksnr_retry_interval *= 2;
        route->ksnr_retry_interval = 
                MAX(route->ksnr_retry_interval,
                    cfs_time_seconds(*ksocknal_tunables.ksnd_min_reconnectms)/1000);
        route->ksnr_retry_interval = 
                MIN(route->ksnr_retry_interval,
                    cfs_time_seconds(*ksocknal_tunables.ksnd_max_reconnectms)/1000);
        
        LASSERT (route->ksnr_retry_interval != 0);
        route->ksnr_timeout = cfs_time_add(cfs_time_current(),
                                           route->ksnr_retry_interval);

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

#if 0           /* irrelevent with only eager routes */
        if (!route->ksnr_deleted) {
                /* make this route least-favourite for re-selection */
                list_del(&route->ksnr_list);
                list_add_tail(&route->ksnr_list, &peer->ksnp_routes);
        }
#endif
        write_unlock_irqrestore (&ksocknal_data.ksnd_global_lock, flags);

        while (!list_empty (&zombies)) {
                tx = list_entry (zombies.next, ksock_tx_t, tx_list);

                CERROR ("Deleting packet type %d len %d %s->%s\n",
                        le32_to_cpu (tx->tx_hdr->type),
                        le32_to_cpu (tx->tx_hdr->payload_length),
                        libcfs_nid2str(le64_to_cpu(tx->tx_hdr->src_nid)),
                        libcfs_nid2str(le64_to_cpu (tx->tx_hdr->dest_nid)));

                list_del (&tx->tx_list);
                /* complete now */
                ksocknal_tx_done (peer, tx, 0);
        }
}

int
ksocknal_connd (void *arg)
{
        long               id = (long)arg;
        char               name[16];
        unsigned long      flags;
        ksock_connreq_t   *cr;
        ksock_route_t     *route;
        int                rc;
        int                did_something;

        snprintf (name, sizeof (name), "socknal_cd%02ld", id);
        libcfs_daemonize (name);
        libcfs_blockallsigs ();

        spin_lock_irqsave (&ksocknal_data.ksnd_connd_lock, flags);

        while (!ksocknal_data.ksnd_shuttingdown) {

                did_something = 0;

                if (!list_empty(&ksocknal_data.ksnd_connd_connreqs)) {
                        /* Connection accepted by the listener */
                        cr = list_entry(ksocknal_data.ksnd_connd_connreqs.next,
                                        ksock_connreq_t, ksncr_list);
                        
                        list_del(&cr->ksncr_list);
                        spin_unlock_irqrestore(&ksocknal_data.ksnd_connd_lock, 
                                               flags);
                        
                        ksocknal_create_conn(cr->ksncr_ni, NULL, 
                                             cr->ksncr_sock, SOCKLND_CONN_NONE);
                        lnet_ni_decref(cr->ksncr_ni);
                        PORTAL_FREE(cr, sizeof(*cr));
                        
                        spin_lock_irqsave(&ksocknal_data.ksnd_connd_lock,
                                          flags);
                        did_something = 1;
                }

                if (!list_empty (&ksocknal_data.ksnd_connd_routes)) {
                        /* Connection request */
                        route = list_entry (ksocknal_data.ksnd_connd_routes.next,
                                            ksock_route_t, ksnr_connd_list);

                        list_del (&route->ksnr_connd_list);
                        spin_unlock_irqrestore (&ksocknal_data.ksnd_connd_lock, flags);

                        ksocknal_connect (route);
                        ksocknal_route_decref(route);

                        spin_lock_irqsave(&ksocknal_data.ksnd_connd_lock,
                                          flags);
                        did_something = 1;
                }

                if (did_something)
                        continue;

                spin_unlock_irqrestore(&ksocknal_data.ksnd_connd_lock,
                                       flags);

                rc = wait_event_interruptible(ksocknal_data.ksnd_connd_waitq,
                                              ksocknal_data.ksnd_shuttingdown ||
                                              !list_empty(&ksocknal_data.ksnd_connd_connreqs) ||
                                              !list_empty(&ksocknal_data.ksnd_connd_routes));

                spin_lock_irqsave(&ksocknal_data.ksnd_connd_lock, flags);
        }

        spin_unlock_irqrestore (&ksocknal_data.ksnd_connd_lock, flags);

        ksocknal_thread_fini ();
        return (0);
}

ksock_conn_t *
ksocknal_find_timed_out_conn (ksock_peer_t *peer) 
{
        /* We're called with a shared lock on ksnd_global_lock */
        ksock_conn_t      *conn;
        struct list_head  *ctmp;

        list_for_each (ctmp, &peer->ksnp_conns) {
                conn = list_entry (ctmp, ksock_conn_t, ksnc_list);

                /* Don't need the {get,put}connsock dance to deref ksnc_sock... */
                LASSERT (!conn->ksnc_closing);

                if (SOCK_ERROR(conn->ksnc_sock) != 0) {
                        ksocknal_conn_addref(conn);

                        switch (SOCK_ERROR(conn->ksnc_sock)) {
                        case ECONNRESET:
                                LCONSOLE_WARN("A connection with %u.%u.%u.%u "
                                              "was reset; they may have "
                                              "rebooted.\n",
                                              HIPQUAD(conn->ksnc_ipaddr));
                                break;
                        case ETIMEDOUT:
                                LCONSOLE_WARN("A connection with %u.%u.%u.%u "
                                              "timed out; the network or that "
                                              "node may be down.\n",
                                              HIPQUAD(conn->ksnc_ipaddr));
                                break;
                        default:
                                LCONSOLE_WARN("An unexpected network error "
                                              "occurred with %u.%u.%u.%u: %d.\n",
                                              HIPQUAD(conn->ksnc_ipaddr),
                                              SOCK_ERROR(conn->ksnc_sock));
                                break;
                        }

                        /* Something (e.g. failed keepalive) set the socket error */
                        CERROR ("Socket error %d: %s %p %d.%d.%d.%d\n",
                                SOCK_ERROR(conn->ksnc_sock), 
                                libcfs_id2str(peer->ksnp_id),
                                conn, HIPQUAD(conn->ksnc_ipaddr));

                        return (conn);
                }

                if (conn->ksnc_rx_started &&
                    cfs_time_aftereq (cfs_time_current(), 
                                      conn->ksnc_rx_deadline)) {
                        /* Timed out incomplete incoming message */
                        ksocknal_conn_addref(conn);
                        LCONSOLE_ERROR("A timeout occurred receiving data from "
                                       "%u.%u.%u.%u; the network or that node "
                                       "may be down.\n",
                                       HIPQUAD(conn->ksnc_ipaddr));
                        CERROR ("Timed out RX from %s %p %d.%d.%d.%d\n",
                                libcfs_id2str(peer->ksnp_id),
                                conn, HIPQUAD(conn->ksnc_ipaddr));
                        return (conn);
                }

                if ((!list_empty (&conn->ksnc_tx_queue) ||
                     SOCK_WMEM_QUEUED(conn->ksnc_sock) != 0) &&
                    cfs_time_aftereq (cfs_time_current(), 
                                      conn->ksnc_tx_deadline)) {
                        /* Timed out messages queued for sending or
                         * buffered in the socket's send buffer */
                        ksocknal_conn_addref(conn);
                        LCONSOLE_ERROR("A timeout occurred sending data to "
                                       "%u.%u.%u.%u; the network or that node "
                                       "may be down.\n",
                                       HIPQUAD(conn->ksnc_ipaddr));
                        CERROR ("Timed out TX to %s %s%d %p %d.%d.%d.%d\n",
                                libcfs_id2str(peer->ksnp_id),
                                list_empty (&conn->ksnc_tx_queue) ? "" : "Q ",
                                SOCK_WMEM_QUEUED(conn->ksnc_sock), conn,
                                HIPQUAD(conn->ksnc_ipaddr));
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

                        CERROR ("Timeout out conn->%s ip %d.%d.%d.%d:%d\n",
                                libcfs_id2str(peer->ksnp_id),
                                HIPQUAD(conn->ksnc_ipaddr),
                                conn->ksnc_port);
                        ksocknal_close_conn_and_siblings (conn, -ETIMEDOUT);
                        
                        /* NB we won't find this one again, but we can't
                         * just proceed with the next peer, since we dropped
                         * ksnd_global_lock and it might be dead already! */
                        ksocknal_conn_decref(conn);
                        goto again;
                }
        }

        read_unlock (&ksocknal_data.ksnd_global_lock);
}

int
ksocknal_reaper (void *arg)
{
        cfs_waitlink_t     wait;
        unsigned long      flags;
        ksock_conn_t      *conn;
        ksock_sched_t     *sched;
        struct list_head   enomem_conns;
        int                nenomem_conns;
        cfs_duration_t     timeout;
        int                i;
        int                peer_index = 0;
        cfs_time_t         deadline = cfs_time_current();

        libcfs_daemonize ("socknal_reaper");
        libcfs_blockallsigs ();

        CFS_INIT_LIST_HEAD(&enomem_conns);
        cfs_waitlink_init (&wait);

        spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);

        while (!ksocknal_data.ksnd_shuttingdown) {

                if (!list_empty (&ksocknal_data.ksnd_deathrow_conns)) {
                        conn = list_entry (ksocknal_data.ksnd_deathrow_conns.next,
                                           ksock_conn_t, ksnc_list);
                        list_del (&conn->ksnc_list);
                        
                        spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

                        ksocknal_terminate_conn (conn);
                        ksocknal_conn_decref(conn);

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

                if (!list_empty (&ksocknal_data.ksnd_enomem_conns)) {
                        list_add(&enomem_conns, &ksocknal_data.ksnd_enomem_conns);
                        list_del_init(&ksocknal_data.ksnd_enomem_conns);
                }

                spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

                /* reschedule all the connections that stalled with ENOMEM... */
                nenomem_conns = 0;
                while (!list_empty (&enomem_conns)) {
                        conn = list_entry (enomem_conns.next,
                                           ksock_conn_t, ksnc_tx_list);
                        list_del (&conn->ksnc_tx_list);

                        sched = conn->ksnc_scheduler;

                        spin_lock_irqsave (&sched->kss_lock, flags);

                        LASSERT (conn->ksnc_tx_scheduled);
                        conn->ksnc_tx_ready = 1;
                        list_add_tail(&conn->ksnc_tx_list,&sched->kss_tx_conns);
                        cfs_waitq_signal (&sched->kss_waitq);

                        spin_unlock_irqrestore (&sched->kss_lock, flags);
                        nenomem_conns++;
                }

                /* careful with the jiffy wrap... */
                while ((timeout = cfs_time_sub(deadline,
                                               cfs_time_current())) <= 0) {
                        const int n = 4;
                        const int p = 1;
                        int       chunk = ksocknal_data.ksnd_peer_hash_size;

                        /* Time to check for timeouts on a few more peers: I do
                         * checks every 'p' seconds on a proportion of the peer
                         * table and I need to check every connection 'n' times
                         * within a timeout interval, to ensure I detect a
                         * timeout on any connection within (n+1)/n times the
                         * timeout interval. */

                        if (*ksocknal_tunables.ksnd_timeout > n * p)
                                chunk = (chunk * n * p) /
                                        *ksocknal_tunables.ksnd_timeout;
                        if (chunk == 0)
                                chunk = 1;

                        for (i = 0; i < chunk; i++) {
                                ksocknal_check_peer_timeouts (peer_index);
                                peer_index = (peer_index + 1) %
                                             ksocknal_data.ksnd_peer_hash_size;
                        }

                        deadline = cfs_time_add(deadline, cfs_time_seconds(p));
                }

                if (nenomem_conns != 0) {
                        /* Reduce my timeout if I rescheduled ENOMEM conns.
                         * This also prevents me getting woken immediately
                         * if any go back on my enomem list. */
                        timeout = SOCKNAL_ENOMEM_RETRY;
                }
                ksocknal_data.ksnd_reaper_waketime =
                        cfs_time_add(cfs_time_current(), timeout);

                set_current_state (TASK_INTERRUPTIBLE);
                cfs_waitq_add (&ksocknal_data.ksnd_reaper_waitq, &wait);

                if (!ksocknal_data.ksnd_shuttingdown &&
                    list_empty (&ksocknal_data.ksnd_deathrow_conns) &&
                    list_empty (&ksocknal_data.ksnd_zombie_conns))
                        cfs_waitq_timedwait (&wait, timeout);

                set_current_state (TASK_RUNNING);
                cfs_waitq_del (&ksocknal_data.ksnd_reaper_waitq, &wait);

                spin_lock_irqsave (&ksocknal_data.ksnd_reaper_lock, flags);
        }

        spin_unlock_irqrestore (&ksocknal_data.ksnd_reaper_lock, flags);

        ksocknal_thread_fini ();
        return (0);
}
