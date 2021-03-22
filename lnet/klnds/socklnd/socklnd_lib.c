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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include "socklnd.h"

int
ksocknal_lib_get_conn_addrs(struct ksock_conn *conn)
{
	int rc = lnet_sock_getaddr(conn->ksnc_sock, true,
				   &conn->ksnc_peeraddr);

	/* Didn't need the {get,put}connsock dance to deref ksnc_sock... */
	LASSERT(!conn->ksnc_closing);

	if (rc != 0) {
		CERROR("Error %d getting sock peer_ni IP\n", rc);
		return rc;
	}

	rc = lnet_sock_getaddr(conn->ksnc_sock, false,
			       &conn->ksnc_myaddr);
	if (rc != 0) {
		CERROR("Error %d getting sock local IP\n", rc);
		return rc;
	}

	return 0;
}

int
ksocknal_lib_zc_capable(struct ksock_conn *conn)
{
	int  caps = conn->ksnc_sock->sk->sk_route_caps;

	if (conn->ksnc_proto == &ksocknal_protocol_v1x)
		return 0;

	/* ZC if the socket supports scatter/gather and doesn't need software
	 * checksums */
	return ((caps & NETIF_F_SG) != 0 && (caps & NETIF_F_CSUM_MASK) != 0);
}

int
ksocknal_lib_send_hdr(struct ksock_conn *conn, struct ksock_tx *tx,
		      struct kvec *scratchiov)
{
	struct socket  *sock = conn->ksnc_sock;
	int		nob = 0;
	int		rc;

	if (*ksocknal_tunables.ksnd_enable_csum	       && /* checksum enabled */
	    conn->ksnc_proto == &ksocknal_protocol_v2x && /* V2.x connection  */
	    tx->tx_nob == tx->tx_resid		       && /* frist sending    */
	    tx->tx_msg.ksm_csum == 0)			  /* not checksummed  */
		ksocknal_lib_csum_tx(tx);

	/* NB we can't trust socket ops to either consume our iovs
	 * or leave them alone. */

	{
#if SOCKNAL_SINGLE_FRAG_TX
		struct kvec scratch;
		struct kvec *scratchiov = &scratch;
		unsigned int niov = 1;
#else
		unsigned int niov = tx->tx_niov;
#endif
		struct msghdr msg = { .msg_flags = MSG_DONTWAIT };

		if (tx->tx_niov) {
			scratchiov[0] = tx->tx_hdr;
			nob += scratchiov[0].iov_len;
		}

		if (!list_empty(&conn->ksnc_tx_queue) ||
		    nob < tx->tx_resid)
			msg.msg_flags |= MSG_MORE;

		rc = kernel_sendmsg(sock, &msg, scratchiov, niov, nob);
	}
	return rc;
}

int
ksocknal_lib_send_kiov(struct ksock_conn *conn, struct ksock_tx *tx,
		       struct kvec *scratchiov)
{
	struct socket *sock = conn->ksnc_sock;
	struct bio_vec *kiov = tx->tx_kiov;
	int            rc;
	int            nob;

	/* Not NOOP message */
	LASSERT(tx->tx_lnetmsg != NULL);

	/* NB we can't trust socket ops to either consume our iovs
	 * or leave them alone. */
	if (tx->tx_msg.ksm_zc_cookies[0] != 0) {
		/* Zero copy is enabled */
		struct sock   *sk = sock->sk;
		struct page   *page = kiov->bv_page;
		int            offset = kiov->bv_offset;
		int            fragsize = kiov->bv_len;
		int            msgflg = MSG_DONTWAIT;

		CDEBUG(D_NET, "page %p + offset %x for %d\n",
			       page, offset, kiov->bv_len);

		if (!list_empty(&conn->ksnc_tx_queue) ||
		    fragsize < tx->tx_resid)
			msgflg |= MSG_MORE;

		rc = sk->sk_prot->sendpage(sk, page,
					   offset, fragsize, msgflg);
	} else {
#if SOCKNAL_SINGLE_FRAG_TX || !SOCKNAL_RISK_KMAP_DEADLOCK
		struct kvec	scratch;
		struct kvec   *scratchiov = &scratch;
		unsigned int	niov = 1;
#else
#ifdef CONFIG_HIGHMEM
#warning "XXX risk of kmap deadlock on multiple frags..."
#endif
		unsigned int  niov = tx->tx_nkiov;
#endif
		struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
		int	      i;

		for (nob = i = 0; i < niov; i++) {
			scratchiov[i].iov_base = kmap(kiov[i].bv_page) +
						 kiov[i].bv_offset;
			nob += scratchiov[i].iov_len = kiov[i].bv_len;
		}

		if (!list_empty(&conn->ksnc_tx_queue) ||
		    nob < tx->tx_resid)
			msg.msg_flags |= MSG_MORE;

		rc = kernel_sendmsg(sock, &msg, scratchiov, niov, nob);

		for (i = 0; i < niov; i++)
			kunmap(kiov[i].bv_page);
	}
	return rc;
}

void
ksocknal_lib_eager_ack(struct ksock_conn *conn)
{
	struct socket *sock = conn->ksnc_sock;

	/* Remind the socket to ACK eagerly.  If I don't, the socket might
	 * think I'm about to send something it could piggy-back the ACK on,
	 * introducing delay in completing zero-copy sends in my peer_ni.
	 */

	tcp_sock_set_quickack(sock->sk, 1);
}

int
ksocknal_lib_recv_iov(struct ksock_conn *conn, struct kvec *scratchiov)
{
#if SOCKNAL_SINGLE_FRAG_RX
	struct kvec  scratch;
	struct kvec *scratchiov = &scratch;
	unsigned int  niov = 1;
#else
	unsigned int  niov = conn->ksnc_rx_niov;
#endif
	struct kvec *iov = conn->ksnc_rx_iov;
	struct msghdr msg = {
		.msg_flags      = 0
	};
        int          nob;
        int          i;
        int          rc;
        int          fragnob;
        int          sum;
        __u32        saved_csum;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */
        LASSERT (niov > 0);

        for (nob = i = 0; i < niov; i++) {
                scratchiov[i] = iov[i];
                nob += scratchiov[i].iov_len;
        }
        LASSERT (nob <= conn->ksnc_rx_nob_wanted);

	rc = kernel_recvmsg(conn->ksnc_sock, &msg, scratchiov, niov, nob,
			    MSG_DONTWAIT);

        saved_csum = 0;
        if (conn->ksnc_proto == &ksocknal_protocol_v2x) {
                saved_csum = conn->ksnc_msg.ksm_csum;
                conn->ksnc_msg.ksm_csum = 0;
        }

        if (saved_csum != 0) {
                /* accumulate checksum */
                for (i = 0, sum = rc; sum > 0; i++, sum -= fragnob) {
                        LASSERT (i < niov);

                        fragnob = iov[i].iov_len;
                        if (fragnob > sum)
                                fragnob = sum;

                        conn->ksnc_rx_csum = ksocknal_csum(conn->ksnc_rx_csum,
                                                           iov[i].iov_base, fragnob);
                }
                conn->ksnc_msg.ksm_csum = saved_csum;
        }

        return rc;
}

static void
ksocknal_lib_kiov_vunmap(void *addr)
{
        if (addr == NULL)
                return;

        vunmap(addr);
}

static void *
ksocknal_lib_kiov_vmap(struct bio_vec *kiov, int niov,
		       struct kvec *iov, struct page **pages)
{
        void             *addr;
        int               nob;
        int               i;

        if (!*ksocknal_tunables.ksnd_zc_recv || pages == NULL)
                return NULL;

        LASSERT (niov <= LNET_MAX_IOV);

        if (niov < 2 ||
            niov < *ksocknal_tunables.ksnd_zc_recv_min_nfrags)
                return NULL;

	for (nob = i = 0; i < niov; i++) {
		if ((kiov[i].bv_offset != 0 && i > 0) ||
		    (kiov[i].bv_offset + kiov[i].bv_len !=
		     PAGE_SIZE && i < niov - 1))
			return NULL;

		pages[i] = kiov[i].bv_page;
		nob += kiov[i].bv_len;
	}

	addr = vmap(pages, niov, VM_MAP, PAGE_KERNEL);
	if (addr == NULL)
		return NULL;

	iov->iov_base = addr + kiov[0].bv_offset;
	iov->iov_len = nob;

	return addr;
}

int
ksocknal_lib_recv_kiov(struct ksock_conn *conn, struct page **pages,
		       struct kvec *scratchiov)
{
#if SOCKNAL_SINGLE_FRAG_RX || !SOCKNAL_RISK_KMAP_DEADLOCK
	struct kvec   scratch;
	struct kvec  *scratchiov = &scratch;
        struct page  **pages      = NULL;
        unsigned int   niov       = 1;
#else
#ifdef CONFIG_HIGHMEM
#warning "XXX risk of kmap deadlock on multiple frags..."
#endif
	unsigned int   niov       = conn->ksnc_rx_nkiov;
#endif
	struct bio_vec *kiov = conn->ksnc_rx_kiov;
	struct msghdr msg = {
		.msg_flags      = 0
	};
        int          nob;
        int          i;
        int          rc;
        void        *base;
        void        *addr;
        int          sum;
        int          fragnob;
	int n;

        /* NB we can't trust socket ops to either consume our iovs
         * or leave them alone. */
	if ((addr = ksocknal_lib_kiov_vmap(kiov, niov, scratchiov, pages)) != NULL) {
		nob = scratchiov[0].iov_len;
		n = 1;

	} else {
		for (nob = i = 0; i < niov; i++) {
			nob += scratchiov[i].iov_len = kiov[i].bv_len;
			scratchiov[i].iov_base = kmap(kiov[i].bv_page) +
						 kiov[i].bv_offset;
		}
		n = niov;
	}

	LASSERT (nob <= conn->ksnc_rx_nob_wanted);

	rc = kernel_recvmsg(conn->ksnc_sock, &msg, scratchiov, n, nob,
			    MSG_DONTWAIT);

	if (conn->ksnc_msg.ksm_csum != 0) {
		for (i = 0, sum = rc; sum > 0; i++, sum -= fragnob) {
			LASSERT(i < niov);

			/* Dang! have to kmap again because I have nowhere to
			 * stash the mapped address.  But by doing it while the
			 * page is still mapped, the kernel just bumps the map
			 * count and returns me the address it stashed.
			 */
			base = kmap(kiov[i].bv_page) + kiov[i].bv_offset;
			fragnob = kiov[i].bv_len;
			if (fragnob > sum)
				fragnob = sum;

			conn->ksnc_rx_csum = ksocknal_csum(conn->ksnc_rx_csum,
							   base, fragnob);

			kunmap(kiov[i].bv_page);
		}
	}

	if (addr != NULL) {
		ksocknal_lib_kiov_vunmap(addr);
	} else {
		for (i = 0; i < niov; i++)
			kunmap(kiov[i].bv_page);
	}

	return rc;
}

void
ksocknal_lib_csum_tx(struct ksock_tx *tx)
{
        int          i;
        __u32        csum;
        void        *base;

	LASSERT(tx->tx_hdr.iov_base == (void *)&tx->tx_msg);
	LASSERT(tx->tx_conn != NULL);
	LASSERT(tx->tx_conn->ksnc_proto == &ksocknal_protocol_v2x);

        tx->tx_msg.ksm_csum = 0;

	csum = ksocknal_csum(~0, (void *)tx->tx_hdr.iov_base,
			     tx->tx_hdr.iov_len);

	for (i = 0; i < tx->tx_nkiov; i++) {
		base = kmap(tx->tx_kiov[i].bv_page) +
			tx->tx_kiov[i].bv_offset;

		csum = ksocknal_csum(csum, base, tx->tx_kiov[i].bv_len);

		kunmap(tx->tx_kiov[i].bv_page);
	}

        if (*ksocknal_tunables.ksnd_inject_csum_error) {
                csum++;
                *ksocknal_tunables.ksnd_inject_csum_error = 0;
        }

        tx->tx_msg.ksm_csum = csum;
}

int
ksocknal_lib_get_conn_tunables(struct ksock_conn *conn, int *txmem, int *rxmem, int *nagle)
{
	struct socket *sock = conn->ksnc_sock;
	struct tcp_sock *tp = tcp_sk(sock->sk);

	if (ksocknal_connsock_addref(conn) < 0) {
		LASSERT(conn->ksnc_closing);
		*txmem = 0;
		*rxmem = 0;
		*nagle = 0;
		return -ESHUTDOWN;
	}

	lnet_sock_getbuf(sock, txmem, rxmem);

	*nagle = !(tp->nonagle & TCP_NAGLE_OFF);

	ksocknal_connsock_decref(conn);


	return 0;
}

int
ksocknal_lib_setup_sock (struct socket *sock)
{
	int rc;
	int keep_idle;
	int keep_intvl;
	int keep_count;
	int do_keepalive;
	struct tcp_sock *tp = tcp_sk(sock->sk);

	sock->sk->sk_allocation = GFP_NOFS;

	/* Ensure this socket aborts active sends immediately when closed. */
	sock_reset_flag(sock->sk, SOCK_LINGER);

	tp->linger2 = -1;

	if (!*ksocknal_tunables.ksnd_nagle)
		tcp_sock_set_nodelay(sock->sk);

	lnet_sock_setbuf(sock,
			 *ksocknal_tunables.ksnd_tx_buffer_size,
			 *ksocknal_tunables.ksnd_rx_buffer_size);

/* TCP_BACKOFF_* sockopt tunables unsupported in stock kernels */
#ifdef SOCKNAL_BACKOFF
	if (*ksocknal_tunables.ksnd_backoff_init > 0) {
		int option = *ksocknal_tunables.ksnd_backoff_init;
#ifdef SOCKNAL_BACKOFF_MS
		option *= 1000;
#endif

		rc = kernel_setsockopt(sock, SOL_TCP, TCP_BACKOFF_INIT,
				       (char *)&option, sizeof(option));
		if (rc != 0) {
			CERROR("Can't set initial tcp backoff %d: %d\n",
			       option, rc);
			return rc;
		}
	}

	if (*ksocknal_tunables.ksnd_backoff_max > 0) {
		int option = *ksocknal_tunables.ksnd_backoff_max;
#ifdef SOCKNAL_BACKOFF_MS
		option *= 1000;
#endif

		rc = kernel_setsockopt(sock, SOL_TCP, TCP_BACKOFF_MAX,
				       (char *)&option, sizeof(option));
		if (rc != 0) {
			CERROR("Can't set maximum tcp backoff %d: %d\n",
			       option, rc);
			return rc;
		}
	}
#endif

	/* snapshot tunables */
	keep_idle  = *ksocknal_tunables.ksnd_keepalive_idle;
	keep_count = *ksocknal_tunables.ksnd_keepalive_count;
	keep_intvl = *ksocknal_tunables.ksnd_keepalive_intvl;

	do_keepalive = (keep_idle > 0 && keep_count > 0 && keep_intvl > 0);

#ifdef HAVE_KERNEL_SETSOCKOPT
	/* open-coded version doesn't work in all kernels, and
	 * there is no helper function, so call kernel_setsockopt()
	 * directly.
	 */
	{
		int option = (do_keepalive ? 1 : 0);
		kernel_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
				  (char *)&option, sizeof(option));
	}
#else
	if (sock->sk->sk_prot->keepalive)
		sock->sk->sk_prot->keepalive(sock->sk, do_keepalive);
	if (do_keepalive)
		sock_set_flag(sock->sk, SOCK_KEEPOPEN);
	else
		sock_reset_flag(sock->sk, SOCK_KEEPOPEN);
#endif /* HAVE_KERNEL_SETSOCKOPT */

	if (!do_keepalive)
		return (0);

	rc = tcp_sock_set_keepidle(sock->sk, keep_idle);
	if (rc != 0) {
		CERROR("Can't set TCP_KEEPIDLE: %d\n", rc);
		return rc;
	}

	rc = tcp_sock_set_keepintvl(sock->sk, keep_intvl);
	if (rc != 0) {
		CERROR("Can't set TCP_KEEPINTVL: %d\n", rc);
		return rc;
	}

	rc = tcp_sock_set_keepcnt(sock->sk, keep_count);
	if (rc != 0) {
		CERROR("Can't set TCP_KEEPCNT: %d\n", rc);
		return rc;
	}

	return (0);
}

void
ksocknal_lib_push_conn(struct ksock_conn *conn)
{
	struct sock *sk;
	struct tcp_sock *tp;
	int nonagle;
	int rc;

	rc = ksocknal_connsock_addref(conn);
	if (rc != 0)                            /* being shut down */
		return;

	sk = conn->ksnc_sock->sk;
	tp = tcp_sk(sk);

	lock_sock(sk);
	nonagle = tp->nonagle;
	tp->nonagle = TCP_NAGLE_OFF;
	release_sock(sk);

	tcp_sock_set_nodelay(conn->ksnc_sock->sk);

	lock_sock(sk);
	tp->nonagle = nonagle;
	release_sock(sk);

	ksocknal_connsock_decref(conn);
}

void ksocknal_read_callback(struct ksock_conn *conn);
void ksocknal_write_callback(struct ksock_conn *conn);
/*
 * socket call back in Linux
 */
static void
#ifdef HAVE_SK_DATA_READY_ONE_ARG
ksocknal_data_ready(struct sock *sk)
#else
ksocknal_data_ready(struct sock *sk, int n)
#endif
{
	struct ksock_conn  *conn;
	ENTRY;

        /* interleave correctly with closing sockets... */
        LASSERT(!in_irq());
	read_lock(&ksocknal_data.ksnd_global_lock);

	conn = sk->sk_user_data;
	if (conn == NULL) {	/* raced with ksocknal_terminate_conn */
		LASSERT(sk->sk_data_ready != &ksocknal_data_ready);
#ifdef HAVE_SK_DATA_READY_ONE_ARG
		sk->sk_data_ready(sk);
#else
		sk->sk_data_ready(sk, n);
#endif
	} else
		ksocknal_read_callback(conn);

	read_unlock(&ksocknal_data.ksnd_global_lock);

	EXIT;
}

static void
ksocknal_write_space (struct sock *sk)
{
	struct ksock_conn  *conn;
        int            wspace;
        int            min_wpace;

        /* interleave correctly with closing sockets... */
        LASSERT(!in_irq());
	read_lock(&ksocknal_data.ksnd_global_lock);

        conn = sk->sk_user_data;
	wspace = sk_stream_wspace(sk);
	min_wpace = sk_stream_min_wspace(sk);

        CDEBUG(D_NET, "sk %p wspace %d low water %d conn %p%s%s%s\n",
               sk, wspace, min_wpace, conn,
               (conn == NULL) ? "" : (conn->ksnc_tx_ready ?
                                      " ready" : " blocked"),
               (conn == NULL) ? "" : (conn->ksnc_tx_scheduled ?
                                      " scheduled" : " idle"),
	       (conn == NULL) ? "" : (list_empty(&conn->ksnc_tx_queue) ?
                                      " empty" : " queued"));

        if (conn == NULL) {             /* raced with ksocknal_terminate_conn */
                LASSERT (sk->sk_write_space != &ksocknal_write_space);
                sk->sk_write_space (sk);

		read_unlock(&ksocknal_data.ksnd_global_lock);
                return;
        }

        if (wspace >= min_wpace) {              /* got enough space */
                ksocknal_write_callback(conn);

                /* Clear SOCK_NOSPACE _after_ ksocknal_write_callback so the
                 * ENOMEM check in ksocknal_transmit is race-free (think about
                 * it). */

                clear_bit (SOCK_NOSPACE, &sk->sk_socket->flags);
        }

	read_unlock(&ksocknal_data.ksnd_global_lock);
}

void
ksocknal_lib_save_callback(struct socket *sock, struct ksock_conn *conn)
{
        conn->ksnc_saved_data_ready = sock->sk->sk_data_ready;
        conn->ksnc_saved_write_space = sock->sk->sk_write_space;
}

void
ksocknal_lib_set_callback(struct socket *sock,  struct ksock_conn *conn)
{
        sock->sk->sk_user_data = conn;
        sock->sk->sk_data_ready = ksocknal_data_ready;
        sock->sk->sk_write_space = ksocknal_write_space;
}

void
ksocknal_lib_reset_callback(struct socket *sock, struct ksock_conn *conn)
{
        /* Remove conn's network callbacks.
         * NB I _have_ to restore the callback, rather than storing a noop,
         * since the socket could survive past this module being unloaded!! */
        sock->sk->sk_data_ready = conn->ksnc_saved_data_ready;
        sock->sk->sk_write_space = conn->ksnc_saved_write_space;

        /* A callback could be in progress already; they hold a read lock
         * on ksnd_global_lock (to serialise with me) and NOOP if
         * sk_user_data is NULL. */
        sock->sk->sk_user_data = NULL;

        return ;
}

int
ksocknal_lib_memory_pressure(struct ksock_conn *conn)
{
	int            rc = 0;
	struct ksock_sched *sched;

	sched = conn->ksnc_scheduler;
	spin_lock_bh(&sched->kss_lock);

	if (!test_bit(SOCK_NOSPACE, &conn->ksnc_sock->flags) &&
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

	spin_unlock_bh(&sched->kss_lock);

	return rc;
}
