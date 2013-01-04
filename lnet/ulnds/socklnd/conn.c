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
 * lnet/ulnds/socklnd/conn.c
 *
 * Author: Maxim Patlasov <maxim@clusterfs.com>
 */

#include "usocklnd.h"

/* Return 1 if the conn is timed out, 0 else */
int
usocklnd_conn_timed_out(usock_conn_t *conn, cfs_time_t current_time)
{
        if (conn->uc_tx_flag && /* sending is in progress */
            cfs_time_aftereq(current_time, conn->uc_tx_deadline))
                return 1;

        if (conn->uc_rx_flag && /* receiving is in progress */
            cfs_time_aftereq(current_time, conn->uc_rx_deadline))
                return 1;

        return 0;
}

void
usocklnd_conn_kill(usock_conn_t *conn)
{
        pthread_mutex_lock(&conn->uc_lock);
        if (conn->uc_state != UC_DEAD)
                usocklnd_conn_kill_locked(conn);
        pthread_mutex_unlock(&conn->uc_lock);
}

/* Mark the conn as DEAD and schedule its deletion */
void
usocklnd_conn_kill_locked(usock_conn_t *conn)
{
        conn->uc_rx_flag = conn->uc_tx_flag = 0;
        conn->uc_state = UC_DEAD;
        usocklnd_add_killrequest(conn);
}

usock_conn_t *
usocklnd_conn_allocate()
{
        usock_conn_t        *conn;
        usock_pollrequest_t *pr;

        LIBCFS_ALLOC (pr, sizeof(*pr));
        if (pr == NULL)
                return NULL;

        LIBCFS_ALLOC (conn, sizeof(*conn));
        if (conn == NULL) {
                LIBCFS_FREE (pr, sizeof(*pr));
                return NULL;
        }
        memset(conn, 0, sizeof(*conn));
        conn->uc_preq = pr;

        LIBCFS_ALLOC (conn->uc_rx_hello,
                      offsetof(ksock_hello_msg_t,
                               kshm_ips[LNET_MAX_INTERFACES]));
        if (conn->uc_rx_hello == NULL) {
                LIBCFS_FREE (pr, sizeof(*pr));
                LIBCFS_FREE (conn, sizeof(*conn));
                return NULL;
        }

        return conn;
}

void
usocklnd_conn_free(usock_conn_t *conn)
{
        usock_pollrequest_t *pr = conn->uc_preq;

        if (pr != NULL)
                LIBCFS_FREE (pr, sizeof(*pr));

        if (conn->uc_rx_hello != NULL)
                LIBCFS_FREE (conn->uc_rx_hello,
                             offsetof(ksock_hello_msg_t,
                                      kshm_ips[LNET_MAX_INTERFACES]));

        LIBCFS_FREE (conn, sizeof(*conn));
}

void
usocklnd_tear_peer_conn(usock_conn_t *conn)
{
        usock_peer_t     *peer = conn->uc_peer;
        int               idx = usocklnd_type2idx(conn->uc_type);
        lnet_ni_t        *ni;
        lnet_process_id_t id;
        int               decref_flag  = 0;
        int               killall_flag = 0;
        void             *rx_lnetmsg   = NULL; 
        CFS_LIST_HEAD    (zombie_txs);

        if (peer == NULL) /* nothing to tear */
                return;

        pthread_mutex_lock(&peer->up_lock);
        pthread_mutex_lock(&conn->uc_lock);

        ni = peer->up_ni;
        id = peer->up_peerid;

        if (peer->up_conns[idx] == conn) {
                if (conn->uc_rx_state == UC_RX_LNET_PAYLOAD) {
                        /* change state not to finalize twice */
                        conn->uc_rx_state = UC_RX_KSM_HEADER;
                        /* stash lnetmsg while holding locks */
                        rx_lnetmsg = conn->uc_rx_lnetmsg;
                }

                /* we cannot finilize txs right now (bug #18844) */
                cfs_list_splice_init(&conn->uc_tx_list, &zombie_txs);

                peer->up_conns[idx] = NULL;
                conn->uc_peer = NULL;
                decref_flag = 1;

                if(conn->uc_errored && !peer->up_errored)
                        peer->up_errored = killall_flag = 1;

                /* prevent queueing new txs to this conn */
                conn->uc_errored = 1;
        }

        pthread_mutex_unlock(&conn->uc_lock);

        if (killall_flag)
                usocklnd_del_conns_locked(peer);

        pthread_mutex_unlock(&peer->up_lock);

        if (!decref_flag)
                return;

        if (rx_lnetmsg != NULL)
                lnet_finalize(ni, rx_lnetmsg, -EIO);
        
        usocklnd_destroy_txlist(ni, &zombie_txs);

        usocklnd_conn_decref(conn);
        usocklnd_peer_decref(peer);

        usocklnd_check_peer_stale(ni, id);
}

/* Remove peer from hash list if all up_conns[i] is NULL &&
 * hash table is the only consumer of the peer */
void
usocklnd_check_peer_stale(lnet_ni_t *ni, lnet_process_id_t id)
{
        usock_peer_t *peer;

        pthread_rwlock_wrlock(&usock_data.ud_peers_lock);
        peer = usocklnd_find_peer_locked(ni, id);

        if (peer == NULL) {
                pthread_rwlock_unlock(&usock_data.ud_peers_lock);
                return;
        }

	if (mt_atomic_read(&peer->up_refcount) == 2) {
                int i;
                for (i = 0; i < N_CONN_TYPES; i++)
                        LASSERT (peer->up_conns[i] == NULL);

                cfs_list_del(&peer->up_list);

                if (peer->up_errored &&
                    (peer->up_peerid.pid & LNET_PID_USERFLAG) == 0)
                        lnet_notify (peer->up_ni, peer->up_peerid.nid, 0,
                                     cfs_time_seconds(peer->up_last_alive));

                usocklnd_peer_decref(peer);
        }

        usocklnd_peer_decref(peer);
        pthread_rwlock_unlock(&usock_data.ud_peers_lock);
}

/* Returns 0 on success, <0 else */
int
usocklnd_create_passive_conn(lnet_ni_t *ni,
                             cfs_socket_t *sock, usock_conn_t **connp)
{
        int           rc;
        __u32         peer_ip;
        int           peer_port;
        usock_conn_t *conn;

        rc = libcfs_sock_getaddr(sock, 1, &peer_ip, &peer_port);
        if (rc)
                return rc;

        LASSERT (peer_port >= 0); /* uc_peer_port is u16 */

        rc = usocklnd_set_sock_options(sock);
        if (rc)
                return rc;

        conn = usocklnd_conn_allocate();
        if (conn == NULL)
                return -ENOMEM;

        usocklnd_rx_hellomagic_state_transition(conn);

        conn->uc_sock = sock;
        conn->uc_peer_ip = peer_ip;
        conn->uc_peer_port = peer_port;
        conn->uc_state = UC_RECEIVING_HELLO;
        conn->uc_pt_idx = usocklnd_ip2pt_idx(peer_ip);
        conn->uc_ni = ni;
        CFS_INIT_LIST_HEAD (&conn->uc_tx_list);
        CFS_INIT_LIST_HEAD (&conn->uc_zcack_list);
        pthread_mutex_init(&conn->uc_lock, NULL);
	mt_atomic_set(&conn->uc_refcount, 1); /* 1 ref for me */

        *connp = conn;
        return 0;
}

/* Returns 0 on success, <0 else */
int
usocklnd_create_active_conn(usock_peer_t *peer, int type,
                            usock_conn_t **connp)
{
        int           rc;
        cfs_socket_t *sock;
        usock_conn_t *conn;
        __u32         dst_ip   = LNET_NIDADDR(peer->up_peerid.nid);
        __u16         dst_port = lnet_acceptor_port();

        conn = usocklnd_conn_allocate();
        if (conn == NULL)
                return -ENOMEM;

        conn->uc_tx_hello = usocklnd_create_cr_hello_tx(peer->up_ni, type,
                                                        peer->up_peerid.nid);
        if (conn->uc_tx_hello == NULL) {
                usocklnd_conn_free(conn);
                return -ENOMEM;
        }

        if (the_lnet.ln_pid & LNET_PID_USERFLAG)
                rc = usocklnd_connect_cli_mode(&sock, dst_ip, dst_port);
        else
                rc = usocklnd_connect_srv_mode(&sock, dst_ip, dst_port);

        if (rc) {
                usocklnd_destroy_tx(NULL, conn->uc_tx_hello);
                usocklnd_conn_free(conn);
                return rc;
        }

        conn->uc_tx_deadline = cfs_time_shift(usock_tuns.ut_timeout);
        conn->uc_tx_flag     = 1;

        conn->uc_sock       = sock;
        conn->uc_peer_ip    = dst_ip;
        conn->uc_peer_port  = dst_port;
        conn->uc_type       = type;
        conn->uc_activeflag = 1;
        conn->uc_state      = UC_CONNECTING;
        conn->uc_pt_idx     = usocklnd_ip2pt_idx(dst_ip);
        conn->uc_ni         = NULL;
        conn->uc_peerid     = peer->up_peerid;
        conn->uc_peer       = peer;

        usocklnd_peer_addref(peer);
        CFS_INIT_LIST_HEAD (&conn->uc_tx_list);
        CFS_INIT_LIST_HEAD (&conn->uc_zcack_list);
        pthread_mutex_init(&conn->uc_lock, NULL);
	mt_atomic_set(&conn->uc_refcount, 1); /* 1 ref for me */

        *connp = conn;
        return 0;
}

/* Returns 0 on success, <0 else */
int
usocklnd_connect_srv_mode(cfs_socket_t **sockp, __u32 dst_ip, __u16 dst_port)
{
        __u16         port;
        cfs_socket_t *sock;
        int           rc;
        int           fatal;

        for (port = LNET_ACCEPTOR_MAX_RESERVED_PORT;
             port >= LNET_ACCEPTOR_MIN_RESERVED_PORT;
             port--) {
                /* Iterate through reserved ports. */
                rc = libcfs_sock_create(&sock, &fatal, 0, port);
                if (rc) {
                        if (fatal)
                                return rc;
                        continue;
                }

                rc = usocklnd_set_sock_options(sock);
                if (rc) {
                        libcfs_sock_release(sock);
                        return rc;
                }

                rc = libcfs_sock_connect(sock, dst_ip, dst_port);
                if (rc == 0) {
                        *sockp = sock;
                        return 0;
                }

                if (rc != -EADDRINUSE && rc != -EADDRNOTAVAIL) {
                        libcfs_sock_release(sock);
                        return rc;
                }

                libcfs_sock_release(sock);
        }

        CERROR("Can't bind to any reserved port\n");
        return rc;
}

/* Returns 0 on success, <0 else */
int
usocklnd_connect_cli_mode(cfs_socket_t **sockp, __u32 dst_ip, __u16 dst_port)
{
        cfs_socket_t *sock;
        int           rc;
        int           fatal;

        rc = libcfs_sock_create(&sock, &fatal, 0, 0);
        if (rc)
                return rc;

        rc = usocklnd_set_sock_options(sock);
        if (rc) {
                libcfs_sock_release(sock);
                return rc;
        }

        rc = libcfs_sock_connect(sock, dst_ip, dst_port);
        if (rc) {
                libcfs_sock_release(sock);
                return rc;
        }

        *sockp = sock;
        return 0;
}

int
usocklnd_set_sock_options(cfs_socket_t *sock)
{
        int rc;

        rc = libcfs_sock_set_nagle(sock, usock_tuns.ut_socknagle);
        if (rc)
                return rc;

        if (usock_tuns.ut_sockbufsiz) {
                rc = libcfs_sock_set_bufsiz(sock, usock_tuns.ut_sockbufsiz);
                if (rc)
                        return rc;
        }

        return libcfs_fcntl_nonblock(sock);
}

usock_tx_t *
usocklnd_create_noop_tx(__u64 cookie)
{
        usock_tx_t *tx;

        LIBCFS_ALLOC (tx, sizeof(usock_tx_t));
        if (tx == NULL)
                return NULL;

        tx->tx_size = sizeof(usock_tx_t);
        tx->tx_lnetmsg = NULL;

        socklnd_init_msg(&tx->tx_msg, KSOCK_MSG_NOOP);
        tx->tx_msg.ksm_zc_cookies[1] = cookie;

        tx->tx_iova[0].iov_base = (void *)&tx->tx_msg;
        tx->tx_iova[0].iov_len = tx->tx_resid = tx->tx_nob =
                offsetof(ksock_msg_t, ksm_u.lnetmsg.ksnm_hdr);
        tx->tx_iov = tx->tx_iova;
        tx->tx_niov = 1;

        return tx;
}

usock_tx_t *
usocklnd_create_tx(lnet_msg_t *lntmsg)
{
        usock_tx_t   *tx;
        unsigned int  payload_niov = lntmsg->msg_niov;
        struct iovec *payload_iov = lntmsg->msg_iov;
        unsigned int  payload_offset = lntmsg->msg_offset;
        unsigned int  payload_nob = lntmsg->msg_len;
        int           size = offsetof(usock_tx_t,
                                      tx_iova[1 + payload_niov]);

        LIBCFS_ALLOC (tx, size);
        if (tx == NULL)
                return NULL;

        tx->tx_size = size;
        tx->tx_lnetmsg = lntmsg;

        tx->tx_resid = tx->tx_nob = sizeof(ksock_msg_t) + payload_nob;

        socklnd_init_msg(&tx->tx_msg, KSOCK_MSG_LNET);
        tx->tx_msg.ksm_u.lnetmsg.ksnm_hdr = lntmsg->msg_hdr;
        tx->tx_iova[0].iov_base = (void *)&tx->tx_msg;
        tx->tx_iova[0].iov_len = sizeof(ksock_msg_t);
        tx->tx_iov = tx->tx_iova;

        tx->tx_niov = 1 +
                lnet_extract_iov(payload_niov, &tx->tx_iov[1],
                                 payload_niov, payload_iov,
                                 payload_offset, payload_nob);

        return tx;
}

void
usocklnd_init_hello_msg(ksock_hello_msg_t *hello,
                        lnet_ni_t *ni, int type, lnet_nid_t peer_nid)
{
        usock_net_t *net = (usock_net_t *)ni->ni_data;

        hello->kshm_magic       = LNET_PROTO_MAGIC;
        hello->kshm_version     = KSOCK_PROTO_V2;
        hello->kshm_nips        = 0;
        hello->kshm_ctype       = type;

        hello->kshm_dst_incarnation = 0; /* not used */
        hello->kshm_src_incarnation = net->un_incarnation;

        hello->kshm_src_pid = the_lnet.ln_pid;
        hello->kshm_src_nid = ni->ni_nid;
        hello->kshm_dst_nid = peer_nid;
        hello->kshm_dst_pid = 0; /* not used */
}

usock_tx_t *
usocklnd_create_hello_tx(lnet_ni_t *ni,
                         int type, lnet_nid_t peer_nid)
{
        usock_tx_t        *tx;
        int                size;
        ksock_hello_msg_t *hello;

        size = sizeof(usock_tx_t) + offsetof(ksock_hello_msg_t, kshm_ips);
        LIBCFS_ALLOC (tx, size);
        if (tx == NULL)
                return NULL;

        tx->tx_size = size;
        tx->tx_lnetmsg = NULL;

        hello = (ksock_hello_msg_t *)&tx->tx_iova[1];
        usocklnd_init_hello_msg(hello, ni, type, peer_nid);

        tx->tx_iova[0].iov_base = (void *)hello;
        tx->tx_iova[0].iov_len = tx->tx_resid = tx->tx_nob =
                offsetof(ksock_hello_msg_t, kshm_ips);
        tx->tx_iov = tx->tx_iova;
        tx->tx_niov = 1;

        return tx;
}

usock_tx_t *
usocklnd_create_cr_hello_tx(lnet_ni_t *ni,
                            int type, lnet_nid_t peer_nid)
{
        usock_tx_t              *tx;
        int                      size;
        lnet_acceptor_connreq_t *cr;
        ksock_hello_msg_t       *hello;

        size = sizeof(usock_tx_t) +
                sizeof(lnet_acceptor_connreq_t) +
                offsetof(ksock_hello_msg_t, kshm_ips);
        LIBCFS_ALLOC (tx, size);
        if (tx == NULL)
                return NULL;

        tx->tx_size = size;
        tx->tx_lnetmsg = NULL;

        cr = (lnet_acceptor_connreq_t *)&tx->tx_iova[1];
        memset(cr, 0, sizeof(*cr));
        cr->acr_magic   = LNET_PROTO_ACCEPTOR_MAGIC;
        cr->acr_version = LNET_PROTO_ACCEPTOR_VERSION;
        cr->acr_nid     = peer_nid;

        hello = (ksock_hello_msg_t *)((char *)cr + sizeof(*cr));
        usocklnd_init_hello_msg(hello, ni, type, peer_nid);

        tx->tx_iova[0].iov_base = (void *)cr;
        tx->tx_iova[0].iov_len = tx->tx_resid = tx->tx_nob =
                sizeof(lnet_acceptor_connreq_t) +
                offsetof(ksock_hello_msg_t, kshm_ips);
        tx->tx_iov = tx->tx_iova;
        tx->tx_niov = 1;

        return tx;
}

void
usocklnd_destroy_tx(lnet_ni_t *ni, usock_tx_t *tx)
{
        lnet_msg_t  *lnetmsg = tx->tx_lnetmsg;
        int          rc = (tx->tx_resid == 0) ? 0 : -EIO;

        LASSERT (ni != NULL || lnetmsg == NULL);

        LIBCFS_FREE (tx, tx->tx_size);

        if (lnetmsg != NULL) /* NOOP and hello go without lnetmsg */
                lnet_finalize(ni, lnetmsg, rc);
}

void
usocklnd_destroy_txlist(lnet_ni_t *ni, cfs_list_t *txlist)
{
        usock_tx_t *tx;

        while (!cfs_list_empty(txlist)) {
                tx = cfs_list_entry(txlist->next, usock_tx_t, tx_list);
                cfs_list_del(&tx->tx_list);

                usocklnd_destroy_tx(ni, tx);
        }
}

void
usocklnd_destroy_zcack_list(cfs_list_t *zcack_list)
{
        usock_zc_ack_t *zcack;

        while (!cfs_list_empty(zcack_list)) {
                zcack = cfs_list_entry(zcack_list->next, usock_zc_ack_t,
                                       zc_list);
                cfs_list_del(&zcack->zc_list);

                LIBCFS_FREE (zcack, sizeof(*zcack));
        }
}

void
usocklnd_destroy_peer(usock_peer_t *peer)
{
        usock_net_t *net = peer->up_ni->ni_data;
        int          i;

        for (i = 0; i < N_CONN_TYPES; i++)
                LASSERT (peer->up_conns[i] == NULL);

        LIBCFS_FREE (peer, sizeof (*peer));

        pthread_mutex_lock(&net->un_lock);
        if(--net->un_peercount == 0)
                pthread_cond_signal(&net->un_cond);
        pthread_mutex_unlock(&net->un_lock);
}

void
usocklnd_destroy_conn(usock_conn_t *conn)
{
        LASSERT (conn->uc_peer == NULL || conn->uc_ni == NULL);

        if (conn->uc_rx_state == UC_RX_LNET_PAYLOAD) {
                LASSERT (conn->uc_peer != NULL);
                lnet_finalize(conn->uc_peer->up_ni, conn->uc_rx_lnetmsg, -EIO);
        }

        if (!cfs_list_empty(&conn->uc_tx_list)) {
                LASSERT (conn->uc_peer != NULL);
                usocklnd_destroy_txlist(conn->uc_peer->up_ni, &conn->uc_tx_list);
        }

        usocklnd_destroy_zcack_list(&conn->uc_zcack_list);

        if (conn->uc_peer != NULL)
                usocklnd_peer_decref(conn->uc_peer);

        if (conn->uc_ni != NULL)
                lnet_ni_decref(conn->uc_ni);

        if (conn->uc_tx_hello)
                usocklnd_destroy_tx(NULL, conn->uc_tx_hello);

        usocklnd_conn_free(conn);
}

int
usocklnd_get_conn_type(lnet_msg_t *lntmsg)
{
        int nob;

        if (the_lnet.ln_pid & LNET_PID_USERFLAG)
                return SOCKLND_CONN_ANY;

        nob = sizeof(ksock_msg_t) + lntmsg->msg_len;

        if (nob >= usock_tuns.ut_min_bulk)
                return SOCKLND_CONN_BULK_OUT;
        else
                return SOCKLND_CONN_CONTROL;
}

int usocklnd_type2idx(int type)
{
        switch (type) {
        case SOCKLND_CONN_ANY:
        case SOCKLND_CONN_CONTROL:
                return 0;
        case SOCKLND_CONN_BULK_IN:
                return 1;
        case SOCKLND_CONN_BULK_OUT:
                return 2;
        default:
                LBUG();
        }
}

usock_peer_t *
usocklnd_find_peer_locked(lnet_ni_t *ni, lnet_process_id_t id)
{
        cfs_list_t       *peer_list = usocklnd_nid2peerlist(id.nid);
        cfs_list_t       *tmp;
        usock_peer_t     *peer;

        cfs_list_for_each (tmp, peer_list) {

                peer = cfs_list_entry (tmp, usock_peer_t, up_list);

                if (peer->up_ni != ni)
                        continue;

                if (peer->up_peerid.nid != id.nid ||
                    peer->up_peerid.pid != id.pid)
                        continue;

                usocklnd_peer_addref(peer);
                return peer;
        }
        return (NULL);
}

int
usocklnd_create_peer(lnet_ni_t *ni, lnet_process_id_t id,
                     usock_peer_t **peerp)
{
        usock_net_t  *net = ni->ni_data;
        usock_peer_t *peer;
        int           i;

        LIBCFS_ALLOC (peer, sizeof (*peer));
        if (peer == NULL)
                return -ENOMEM;

        for (i = 0; i < N_CONN_TYPES; i++)
                peer->up_conns[i] = NULL;

        peer->up_peerid       = id;
        peer->up_ni           = ni;
        peer->up_incrn_is_set = 0;
        peer->up_errored      = 0;
        peer->up_last_alive   = 0;
	mt_atomic_set(&peer->up_refcount, 1); /* 1 ref for caller */
        pthread_mutex_init(&peer->up_lock, NULL);

        pthread_mutex_lock(&net->un_lock);
        net->un_peercount++;
        pthread_mutex_unlock(&net->un_lock);

        *peerp = peer;
        return 0;
}

/* Safely create new peer if needed. Save result in *peerp.
 * Returns 0 on success, <0 else */
int
usocklnd_find_or_create_peer(lnet_ni_t *ni, lnet_process_id_t id,
                             usock_peer_t **peerp)
{
        int           rc;
        usock_peer_t *peer;
        usock_peer_t *peer2;
        usock_net_t  *net = ni->ni_data;

        pthread_rwlock_rdlock(&usock_data.ud_peers_lock);
        peer = usocklnd_find_peer_locked(ni, id);
        pthread_rwlock_unlock(&usock_data.ud_peers_lock);

        if (peer != NULL)
                goto find_or_create_peer_done;

        rc = usocklnd_create_peer(ni, id, &peer);
        if (rc)
                return rc;

        pthread_rwlock_wrlock(&usock_data.ud_peers_lock);
        peer2 = usocklnd_find_peer_locked(ni, id);
        if (peer2 == NULL) {
                if (net->un_shutdown) {
                        pthread_rwlock_unlock(&usock_data.ud_peers_lock);
                        usocklnd_peer_decref(peer); /* should destroy peer */
                        CERROR("Can't create peer: network shutdown\n");
                        return -ESHUTDOWN;
                }

                /* peer table will take 1 of my refs on peer */
                usocklnd_peer_addref(peer);
                cfs_list_add_tail (&peer->up_list,
                                   usocklnd_nid2peerlist(id.nid));
        } else {
                usocklnd_peer_decref(peer); /* should destroy peer */
                peer = peer2;
        }
        pthread_rwlock_unlock(&usock_data.ud_peers_lock);

  find_or_create_peer_done:
        *peerp = peer;
        return 0;
}

/* NB: both peer and conn locks are held */
static int
usocklnd_enqueue_zcack(usock_conn_t *conn, usock_zc_ack_t *zc_ack)
{
        if (conn->uc_state == UC_READY &&
            cfs_list_empty(&conn->uc_tx_list) &&
            cfs_list_empty(&conn->uc_zcack_list) &&
            !conn->uc_sending) {
                int rc = usocklnd_add_pollrequest(conn, POLL_TX_SET_REQUEST,
                                                  POLLOUT);
                if (rc != 0)
                        return rc;
        }

        cfs_list_add_tail(&zc_ack->zc_list, &conn->uc_zcack_list);
        return 0;
}

/* NB: both peer and conn locks are held
 * NB: if sending isn't in progress.  the caller *MUST* send tx
 * immediately after we'll return */
static void
usocklnd_enqueue_tx(usock_conn_t *conn, usock_tx_t *tx,
                    int *send_immediately)
{
        if (conn->uc_state == UC_READY &&
            cfs_list_empty(&conn->uc_tx_list) &&
            cfs_list_empty(&conn->uc_zcack_list) &&
            !conn->uc_sending) {
                conn->uc_sending = 1;
                *send_immediately = 1;
                return;
        }

        *send_immediately = 0;
        cfs_list_add_tail(&tx->tx_list, &conn->uc_tx_list);
}

/* Safely create new conn if needed. Save result in *connp.
 * Returns 0 on success, <0 else */
int
usocklnd_find_or_create_conn(usock_peer_t *peer, int type,
                             usock_conn_t **connp,
                             usock_tx_t *tx, usock_zc_ack_t *zc_ack,
                             int *send_immediately)
{
        usock_conn_t *conn;
        int           idx;
        int           rc;
        lnet_pid_t    userflag = peer->up_peerid.pid & LNET_PID_USERFLAG;

        if (userflag)
                type = SOCKLND_CONN_ANY;

        idx = usocklnd_type2idx(type);

        pthread_mutex_lock(&peer->up_lock);
        if (peer->up_conns[idx] != NULL) {
                conn = peer->up_conns[idx];
                LASSERT(conn->uc_type == type);
        } else {
                if (userflag) {
                        CERROR("Refusing to create a connection to "
                               "userspace process %s\n",
                               libcfs_id2str(peer->up_peerid));
                        rc = -EHOSTUNREACH;
                        goto find_or_create_conn_failed;
                }

                rc = usocklnd_create_active_conn(peer, type, &conn);
                if (rc) {
                        peer->up_errored = 1;
                        usocklnd_del_conns_locked(peer);
                        goto find_or_create_conn_failed;
                }

                /* peer takes 1 of conn refcount */
                usocklnd_link_conn_to_peer(conn, peer, idx);

                rc = usocklnd_add_pollrequest(conn, POLL_ADD_REQUEST, POLLOUT);
                if (rc) {
                        peer->up_conns[idx] = NULL;
                        usocklnd_conn_decref(conn); /* should destroy conn */
                        goto find_or_create_conn_failed;
                }
                usocklnd_wakeup_pollthread(conn->uc_pt_idx);
        }

        pthread_mutex_lock(&conn->uc_lock);
        LASSERT(conn->uc_peer == peer);

        LASSERT(tx == NULL || zc_ack == NULL);
        if (tx != NULL) {
                /* usocklnd_tear_peer_conn() could signal us stop queueing */
                if (conn->uc_errored) {
                        rc = -EIO;
                        pthread_mutex_unlock(&conn->uc_lock);
                        goto find_or_create_conn_failed;
                }

                usocklnd_enqueue_tx(conn, tx, send_immediately);
        } else {
                rc = usocklnd_enqueue_zcack(conn, zc_ack);
                if (rc != 0) {
                        usocklnd_conn_kill_locked(conn);
                        pthread_mutex_unlock(&conn->uc_lock);
                        goto find_or_create_conn_failed;
                }
        }
        pthread_mutex_unlock(&conn->uc_lock);

        usocklnd_conn_addref(conn);
        pthread_mutex_unlock(&peer->up_lock);

        *connp = conn;
        return 0;

  find_or_create_conn_failed:
        pthread_mutex_unlock(&peer->up_lock);
        return rc;
}

void
usocklnd_link_conn_to_peer(usock_conn_t *conn, usock_peer_t *peer, int idx)
{
        peer->up_conns[idx] = conn;
        peer->up_errored    = 0; /* this new fresh conn will try
                                  * revitalize even stale errored peer */
}

int
usocklnd_invert_type(int type)
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
                return SOCKLND_CONN_NONE;
        }
}

void
usocklnd_conn_new_state(usock_conn_t *conn, int new_state)
{
        pthread_mutex_lock(&conn->uc_lock);
        if (conn->uc_state != UC_DEAD)
                conn->uc_state = new_state;
        pthread_mutex_unlock(&conn->uc_lock);
}

/* NB: peer is locked by caller */
void
usocklnd_cleanup_stale_conns(usock_peer_t *peer, __u64 incrn,
                             usock_conn_t *skip_conn)
{
        int i;

        if (!peer->up_incrn_is_set) {
                peer->up_incarnation = incrn;
                peer->up_incrn_is_set = 1;
                return;
        }

        if (peer->up_incarnation == incrn)
                return;

        peer->up_incarnation = incrn;

        for (i = 0; i < N_CONN_TYPES; i++) {
                usock_conn_t *conn = peer->up_conns[i];

                if (conn == NULL || conn == skip_conn)
                        continue;

                pthread_mutex_lock(&conn->uc_lock);
                LASSERT (conn->uc_peer == peer);
                conn->uc_peer = NULL;
                peer->up_conns[i] = NULL;
                if (conn->uc_state != UC_DEAD)
                        usocklnd_conn_kill_locked(conn);
                pthread_mutex_unlock(&conn->uc_lock);

                usocklnd_conn_decref(conn);
                usocklnd_peer_decref(peer);
        }
}

/* RX state transition to UC_RX_HELLO_MAGIC: update RX part to receive
 * MAGIC part of hello and set uc_rx_state
 */
void
usocklnd_rx_hellomagic_state_transition(usock_conn_t *conn)
{
        LASSERT(conn->uc_rx_hello != NULL);

        conn->uc_rx_niov = 1;
        conn->uc_rx_iov = conn->uc_rx_iova;
        conn->uc_rx_iov[0].iov_base = &conn->uc_rx_hello->kshm_magic;
        conn->uc_rx_iov[0].iov_len =
                conn->uc_rx_nob_wanted =
                conn->uc_rx_nob_left =
                sizeof(conn->uc_rx_hello->kshm_magic);

        conn->uc_rx_state = UC_RX_HELLO_MAGIC;

        conn->uc_rx_flag = 1; /* waiting for incoming hello */
        conn->uc_rx_deadline = cfs_time_shift(usock_tuns.ut_timeout);
}

/* RX state transition to UC_RX_HELLO_VERSION: update RX part to receive
 * VERSION part of hello and set uc_rx_state
 */
void
usocklnd_rx_helloversion_state_transition(usock_conn_t *conn)
{
        LASSERT(conn->uc_rx_hello != NULL);

        conn->uc_rx_niov = 1;
        conn->uc_rx_iov = conn->uc_rx_iova;
        conn->uc_rx_iov[0].iov_base = &conn->uc_rx_hello->kshm_version;
        conn->uc_rx_iov[0].iov_len =
                conn->uc_rx_nob_wanted =
                conn->uc_rx_nob_left =
                sizeof(conn->uc_rx_hello->kshm_version);

        conn->uc_rx_state = UC_RX_HELLO_VERSION;
}

/* RX state transition to UC_RX_HELLO_BODY: update RX part to receive
 * the rest  of hello and set uc_rx_state
 */
void
usocklnd_rx_hellobody_state_transition(usock_conn_t *conn)
{
        LASSERT(conn->uc_rx_hello != NULL);

        conn->uc_rx_niov = 1;
        conn->uc_rx_iov = conn->uc_rx_iova;
        conn->uc_rx_iov[0].iov_base = &conn->uc_rx_hello->kshm_src_nid;
        conn->uc_rx_iov[0].iov_len =
                conn->uc_rx_nob_wanted =
                conn->uc_rx_nob_left =
                offsetof(ksock_hello_msg_t, kshm_ips) -
                offsetof(ksock_hello_msg_t, kshm_src_nid);

        conn->uc_rx_state = UC_RX_HELLO_BODY;
}

/* RX state transition to UC_RX_HELLO_IPS: update RX part to receive
 * array of IPs and set uc_rx_state
 */
void
usocklnd_rx_helloIPs_state_transition(usock_conn_t *conn)
{
        LASSERT(conn->uc_rx_hello != NULL);

        conn->uc_rx_niov = 1;
        conn->uc_rx_iov = conn->uc_rx_iova;
        conn->uc_rx_iov[0].iov_base = &conn->uc_rx_hello->kshm_ips;
        conn->uc_rx_iov[0].iov_len =
                conn->uc_rx_nob_wanted =
                conn->uc_rx_nob_left =
                conn->uc_rx_hello->kshm_nips *
                sizeof(conn->uc_rx_hello->kshm_ips[0]);

        conn->uc_rx_state = UC_RX_HELLO_IPS;
}

/* RX state transition to UC_RX_LNET_HEADER: update RX part to receive
 * LNET header and set uc_rx_state
 */
void
usocklnd_rx_lnethdr_state_transition(usock_conn_t *conn)
{
        conn->uc_rx_niov = 1;
        conn->uc_rx_iov = conn->uc_rx_iova;
        conn->uc_rx_iov[0].iov_base = &conn->uc_rx_msg.ksm_u.lnetmsg;
        conn->uc_rx_iov[0].iov_len =
                conn->uc_rx_nob_wanted =
                conn->uc_rx_nob_left =
                sizeof(ksock_lnet_msg_t);

        conn->uc_rx_state = UC_RX_LNET_HEADER;
        conn->uc_rx_flag = 1;
}

/* RX state transition to UC_RX_KSM_HEADER: update RX part to receive
 * KSM header and set uc_rx_state
 */
void
usocklnd_rx_ksmhdr_state_transition(usock_conn_t *conn)
{
        conn->uc_rx_niov = 1;
        conn->uc_rx_iov = conn->uc_rx_iova;
        conn->uc_rx_iov[0].iov_base = &conn->uc_rx_msg;
        conn->uc_rx_iov[0].iov_len =
                conn->uc_rx_nob_wanted =
                conn->uc_rx_nob_left =
                offsetof(ksock_msg_t, ksm_u);

        conn->uc_rx_state = UC_RX_KSM_HEADER;
        conn->uc_rx_flag = 0;
}

/* RX state transition to UC_RX_SKIPPING: update RX part for
 * skipping and set uc_rx_state
 */
void
usocklnd_rx_skipping_state_transition(usock_conn_t *conn)
{
        static char    skip_buffer[4096];

        int            nob;
        unsigned int   niov = 0;
        int            skipped = 0;
        int            nob_to_skip = conn->uc_rx_nob_left;

        LASSERT(nob_to_skip != 0);

        conn->uc_rx_iov = conn->uc_rx_iova;

        /* Set up to skip as much as possible now.  If there's more left
         * (ran out of iov entries) we'll get called again */

        do {
                nob = MIN (nob_to_skip, sizeof(skip_buffer));

                conn->uc_rx_iov[niov].iov_base = skip_buffer;
                conn->uc_rx_iov[niov].iov_len  = nob;
                niov++;
                skipped += nob;
                nob_to_skip -=nob;

        } while (nob_to_skip != 0 &&    /* mustn't overflow conn's rx iov */
                 niov < sizeof(conn->uc_rx_iova) / sizeof (struct iovec));

        conn->uc_rx_niov = niov;
        conn->uc_rx_nob_wanted = skipped;

        conn->uc_rx_state = UC_RX_SKIPPING;
}
