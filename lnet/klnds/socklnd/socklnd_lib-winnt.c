/*
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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/socklnd/socklnd_lib-winnt.c
 *
 * windows socknal library
 */

#include "socklnd.h"

# if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
static cfs_sysctl_table_t ksocknal_ctl_table[21];

cfs_sysctl_table_t ksocknal_top_ctl_table[] = {
        {
                /* ctl_name */  200,
                /* procname */  "socknal",
                /* data     */  NULL,
                /* maxlen   */  0,
                /* mode     */  0555,
                /* child    */  ksocknal_ctl_table
        },
        { 0 }
};

int
ksocknal_lib_tunables_init ()
{
        int    i = 0;
        int    j = 1;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "timeout";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_timeout;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "credits";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_credits;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0444;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "peer_credits";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_peertxcredits;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0444;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "peer_buffer_credits";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_peerrtrcredits;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0444;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "nconnds";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_nconnds;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0444;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;


        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "min_reconnectms";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_min_reconnectms;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0444;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "max_reconnectms";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_max_reconnectms;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0444;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "eager_ack";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_eager_ack;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "zero_copy";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_zc_min_payload;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "typed";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_typed_conns;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0444;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "min_bulk";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_min_bulk;
        ksocknal_ctl_table[i].maxlen   = sizeof (int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "rx_buffer_size";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_rx_buffer_size;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "tx_buffer_size";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_tx_buffer_size;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "nagle";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_nagle;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "round_robin";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_round_robin;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

#ifdef CPU_AFFINITY
        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "irq_affinity";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_irq_affinity;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;
#endif

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "keepalive_idle";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_keepalive_idle;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "keepalive_count";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_keepalive_count;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "keepalive_intvl";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_keepalive_intvl;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

#ifdef SOCKNAL_BACKOFF
        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "backoff_init";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_backoff_init;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;

        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "backoff_max";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_backoff_max;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;
#endif

#if SOCKNAL_VERSION_DEBUG
        ksocknal_ctl_table[i].ctl_name = j++;
        ksocknal_ctl_table[i].procname = "protocol";
        ksocknal_ctl_table[i].data     = ksocknal_tunables.ksnd_protocol;
        ksocknal_ctl_table[i].maxlen   = sizeof(int);
        ksocknal_ctl_table[i].mode     = 0644;
        ksocknal_ctl_table[i].proc_handler = &proc_dointvec;
        i++;
#endif

        LASSERT (j == i + 1);
        LASSERT (i <= sizeof(ksocknal_ctl_table)/sizeof(ksocknal_ctl_table[0]));

        ksocknal_tunables.ksnd_sysctl =
                cfs_register_sysctl_table(ksocknal_top_ctl_table, 0);

        if (ksocknal_tunables.ksnd_sysctl == NULL)
                CWARN("Can't setup /proc tunables\n");

        return 0;
}

void
ksocknal_lib_tunables_fini ()
{
        if (ksocknal_tunables.ksnd_sysctl != NULL)
                cfs_unregister_sysctl_table(ksocknal_tunables.ksnd_sysctl);
}
#else
int
ksocknal_lib_tunables_init ()
{
        return 0;
}

void
ksocknal_lib_tunables_fini ()
{
}
#endif /* # if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM */

void
ksocknal_lib_bind_irq (unsigned int irq)
{
}

int
ksocknal_lib_get_conn_addrs (ksock_conn_t *conn)
{
        int rc = libcfs_sock_getaddr(conn->ksnc_sock, 1,
                                     &conn->ksnc_ipaddr,
                                     &conn->ksnc_port);

        /* Didn't need the {get,put}connsock dance to deref ksnc_sock... */
        LASSERT (!conn->ksnc_closing);

        if (rc != 0) {
                CERROR ("Error %d getting sock peer IP\n", rc);
                return rc;
        }

        rc = libcfs_sock_getaddr(conn->ksnc_sock, 0,
				 &conn->ksnc_myipaddr, NULL);
        if (rc != 0) {
                CERROR ("Error %d getting sock local IP\n", rc);
                return rc;
        }

        return 0;
}

unsigned int
ksocknal_lib_sock_irq (struct socket *sock)
{
        return 0;
}

int
ksocknal_lib_send_iov (ksock_conn_t *conn, ksock_tx_t *tx)
{
        struct socket *sock = conn->ksnc_sock;

        int            nob;
        int            rc;
        int            flags;


        if (*ksocknal_tunables.ksnd_enable_csum        && /* checksum enabled */
            conn->ksnc_proto == &ksocknal_protocol_v2x && /* V2.x connection  */
            tx->tx_nob == tx->tx_resid                 && /* frist sending    */
            tx->tx_msg.ksm_csum == 0)                     /* not checksummed  */
                ksocknal_lib_csum_tx(tx);

        nob = ks_query_iovs_length(tx->tx_iov, tx->tx_niov);
        flags = (!cfs_list_empty (&conn->ksnc_tx_queue) || nob < tx->tx_resid) ? 
                (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT;
        rc = ks_send_iovs(sock, tx->tx_iov, tx->tx_niov, flags, 0);

        KsPrint((4, "ksocknal_lib_send_iov: conn %p sock %p rc %d\n",
                     conn, sock, rc));
        return rc;
}

int
ksocknal_lib_send_kiov (ksock_conn_t *conn, ksock_tx_t *tx)
{
        struct socket *sock = conn->ksnc_sock;
        lnet_kiov_t    *kiov = tx->tx_kiov;
        int            rc;
        int            nob;
        int            nkiov;
        int            flags;

        nkiov = tx->tx_nkiov;
        nob = ks_query_kiovs_length(tx->tx_kiov, nkiov);
        flags = (!cfs_list_empty (&conn->ksnc_tx_queue) || nob < tx->tx_resid) ? 
                (MSG_DONTWAIT | MSG_MORE) : MSG_DONTWAIT;
        rc = ks_send_kiovs(sock, tx->tx_kiov, nkiov, flags, 0);

        KsPrint((4, "ksocknal_lib_send_kiov: conn %p sock %p rc %d\n",
                    conn, sock, rc));
        return rc;
}

int
ksocknal_lib_recv_iov (ksock_conn_t *conn)
{
        struct iovec *iov = conn->ksnc_rx_iov;
        int           rc;
        int           size;

        /* receive payload from tsdu queue */
        rc = ks_recv_iovs (conn->ksnc_sock, iov, conn->ksnc_rx_niov,
                           MSG_DONTWAIT, 0);

        /* calcuate package checksum */
        if (rc > 0) {

                int     i;
                int     fragnob;
                int     sum;
                __u32   saved_csum = 0;

                if (conn->ksnc_proto == &ksocknal_protocol_v2x) {
                        saved_csum = conn->ksnc_msg.ksm_csum;
                        conn->ksnc_msg.ksm_csum = 0;
                }

                if (saved_csum != 0) {

                        /* accumulate checksum */
                        for (i = 0, sum = rc; sum > 0; i++, sum -= fragnob) {
                                LASSERT (i < conn->ksnc_rx_niov);

                                fragnob = iov[i].iov_len;
                                if (fragnob > sum)
                                        fragnob = sum;

                                conn->ksnc_rx_csum = ksocknal_csum(conn->ksnc_rx_csum,
                                                                   iov[i].iov_base, fragnob);
                        }
                        conn->ksnc_msg.ksm_csum = saved_csum;
                }
        }

        KsPrint((4, "ksocknal_lib_recv_iov: conn %p sock %p rc %d.\n",
                    conn, conn->ksnc_sock, rc));
        return rc;
}

int
ksocknal_lib_recv_kiov (ksock_conn_t *conn)
{
        lnet_kiov_t  *kiov = conn->ksnc_rx_kiov;
        int           rc;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone, so we only receive 1 frag at a time. */
        LASSERT (conn->ksnc_rx_nkiov > 0);

        /* receive payload from tsdu queue */
        rc = ks_recv_kiovs (conn->ksnc_sock, kiov, conn->ksnc_rx_nkiov,
                            MSG_DONTWAIT, 0);

        if (rc > 0 && conn->ksnc_msg.ksm_csum != 0) {

                int          i;
                char        *base;
                int          sum;
                int          fragnob;

                for (i = 0, sum = rc; sum > 0; i++, sum -= fragnob) {

                        LASSERT (i < conn->ksnc_rx_nkiov);

                        base = (char *)(kiov[i].kiov_page->addr) + kiov[i].kiov_offset;
                        fragnob = kiov[i].kiov_len;
                        if (fragnob > sum)
                                fragnob = sum;

                        conn->ksnc_rx_csum = ksocknal_csum(conn->ksnc_rx_csum,
                                                           base, fragnob);
                }
        }

        KsPrint((4, "ksocknal_lib_recv_kiov: conn %p sock %p rc %d.\n",
                    conn, conn->ksnc_sock, rc));
        return rc;
}

void
ksocknal_lib_eager_ack (ksock_conn_t *conn)
{
        __u32   option = 1;
        int     rc = 0;
                
        rc = ks_set_tcp_option(
                conn->ksnc_sock, TCP_SOCKET_NODELAY,
                &option, sizeof(option) );
        if (rc != 0) {
                CERROR("Can't disable nagle: %d\n", rc);
        }
}

int
ksocknal_lib_get_conn_tunables (ksock_conn_t *conn, int *txmem, int *rxmem, int *nagle)
{
        ks_tconn_t *    tconn = conn->ksnc_sock;
        int             len;
        int             rc;

        ks_get_tconn (tconn);
        *txmem = *rxmem = 0;
        len = sizeof(*nagle);
        rc = ks_get_tcp_option(tconn, TCP_SOCKET_NODELAY, (__u32 *)nagle, &len);
        ks_put_tconn (tconn);

        KsPrint((2, "ksocknal_get_conn_tunables: nodelay = %d rc = %d\n", *nagle, rc));

        if (rc == 0)
                *nagle = !*nagle;
        else
                *txmem = *rxmem = *nagle = 0;
                
        return (rc);
}

int
ksocknal_lib_setup_sock (struct socket *sock)
{
        int             rc;

        int             keep_idle;
        int             keep_count;
        int             keep_intvl;
        int             keep_alive;

        __u32           option;

#if 0
        /* set the window size */
        tconn->kstc_snd_wnd = ksocknal_tunables.ksnd_buffer_size;
        tconn->kstc_rcv_wnd = ksocknal_tunables.ksnd_buffer_size;
#endif

        /* disable nagle */
        if (!ksocknal_tunables.ksnd_nagle) {
                option = 1;
                
                rc = ks_set_tcp_option(
                            sock, TCP_SOCKET_NODELAY,
                            &option, sizeof (option));
                if (rc != 0) {
                        CERROR ("Can't disable nagle: %d\n", rc);
                        return (rc);
                }
        }

        /* snapshot tunables */
        keep_idle  = *ksocknal_tunables.ksnd_keepalive_idle;
        keep_count = *ksocknal_tunables.ksnd_keepalive_count;
        keep_intvl = *ksocknal_tunables.ksnd_keepalive_intvl;
        
        keep_alive = (keep_idle > 0 && keep_count > 0 && keep_intvl > 0);

        option = (__u32)(keep_alive ? 1 : 0);

        rc = ks_set_tcp_option(
                    sock, TCP_SOCKET_KEEPALIVE,
                    &option, sizeof (option));
        if (rc != 0) {
                CERROR ("Can't disable nagle: %d\n", rc);
                return (rc);
        }

        return (0);
}

void
ksocknal_lib_push_conn (ksock_conn_t *conn)
{
        ks_tconn_t *    tconn;
        __u32           nagle;
        __u32           val = 1;
        int             rc;

        tconn = conn->ksnc_sock;

        ks_get_tconn(tconn);

	spin_lock(&tconn->kstc_lock);
        if (tconn->kstc_type == kstt_sender) {
                nagle = tconn->sender.kstc_info.nagle;
                tconn->sender.kstc_info.nagle = 0;
        } else {
                LASSERT(tconn->kstc_type == kstt_child);
                nagle = tconn->child.kstc_info.nagle;
                tconn->child.kstc_info.nagle = 0;
        }

	spin_unlock(&tconn->kstc_lock);

        val = 1;
        rc = ks_set_tcp_option(
                    tconn,
                    TCP_SOCKET_NODELAY,
                    &(val),
                    sizeof(__u32)
                    );

        LASSERT (rc == 0);
	spin_lock(&tconn->kstc_lock);

	if (tconn->kstc_type == kstt_sender) {
		tconn->sender.kstc_info.nagle = nagle;
	} else {
		LASSERT(tconn->kstc_type == kstt_child);
		tconn->child.kstc_info.nagle = nagle;
	}
	spin_unlock(&tconn->kstc_lock);
        ks_put_tconn(tconn);
}

void
ksocknal_lib_csum_tx(ksock_tx_t *tx)
{
        int          i;
        __u32        csum;
        void        *base;

        LASSERT(tx->tx_iov[0].iov_base == (void *)&tx->tx_msg);
        LASSERT(tx->tx_conn != NULL);
        LASSERT(tx->tx_conn->ksnc_proto == &ksocknal_protocol_v2x);

        tx->tx_msg.ksm_csum = 0;

        csum = ksocknal_csum(~0, (void *)tx->tx_iov[0].iov_base,
                             tx->tx_iov[0].iov_len);

        if (tx->tx_kiov != NULL) {
                for (i = 0; i < tx->tx_nkiov; i++) {
                        base = (PUCHAR)(tx->tx_kiov[i].kiov_page->addr) +
                               tx->tx_kiov[i].kiov_offset;

                        csum = ksocknal_csum(csum, base, tx->tx_kiov[i].kiov_len);
                }
        } else {
                for (i = 1; i < tx->tx_niov; i++)
                        csum = ksocknal_csum(csum, tx->tx_iov[i].iov_base,
                                             tx->tx_iov[i].iov_len);
        }

        if (*ksocknal_tunables.ksnd_inject_csum_error) {
                csum++;
                *ksocknal_tunables.ksnd_inject_csum_error = 0;
        }

        tx->tx_msg.ksm_csum = csum;
}

void ksocknal_schedule_callback(struct socket*sock, int mode)
{
        ksock_conn_t * conn = (ksock_conn_t *) sock->kstc_conn;

	read_lock(&ksocknal_data.ksnd_global_lock);
        if (mode) {
                ksocknal_write_callback(conn);
        } else {
                ksocknal_read_callback(conn);
        }
	read_unlock(&ksocknal_data.ksnd_global_lock);
}

void
ksocknal_tx_fini_callback(ksock_conn_t * conn, ksock_tx_t * tx)
{
	/* remove tx/conn from conn's outgoing queue */
	spin_lock_bh(&conn->ksnc_scheduler->kss_lock);
	cfs_list_del(&tx->tx_list);
	if (cfs_list_empty(&conn->ksnc_tx_queue))
		cfs_list_del(&conn->ksnc_tx_list);

	spin_unlock_bh(&conn->ksnc_scheduler->kss_lock);

	/* complete send; tx -ref */
	ksocknal_tx_decref(tx);
}

void
ksocknal_lib_save_callback(struct socket *sock, ksock_conn_t *conn)
{
}

void
ksocknal_lib_set_callback(struct socket *sock,  ksock_conn_t *conn)
{
        sock->kstc_conn      = conn;
        sock->kstc_sched_cb  = ksocknal_schedule_callback;
}

void
ksocknal_lib_reset_callback(struct socket *sock, ksock_conn_t *conn)
{
        sock->kstc_conn      = NULL;
        sock->kstc_sched_cb  = NULL;
}

int
ksocknal_lib_zc_capable(ksock_conn_t *conn)
{
        return 0;
}

int
ksocknal_lib_memory_pressure(ksock_conn_t *conn)
{
        return 0;
}

int
ksocknal_lib_bind_thread_to_cpu(int id)
{
        return 0;
}
