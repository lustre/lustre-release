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

#ifndef __LIBCFS_LINUX_NET_H__
#define __LIBCFS_LINUX_NET_H__

#ifdef HAVE_KERNEL_SETSOCKOPT

#include <net/tcp.h>

static inline void tcp_sock_set_quickack(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	kernel_setsockopt(sock, SOL_TCP, TCP_QUICKACK,
			  (char *)&opt, sizeof(opt));
}

#if !defined(HAVE_TCP_SOCK_SET_NODELAY)
static inline void tcp_sock_set_nodelay(struct sock *sk)
{
	int opt = 1;
	struct socket *sock = sk->sk_socket;

	kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
			  (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_NODELAY */

#if !defined(HAVE_TCP_SOCK_SET_KEEPIDLE)
static inline int tcp_sock_set_keepidle(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPIDLE,
				 (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_KEEPIDLE */

static inline int tcp_sock_set_keepintvl(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL,
				 (char *)&opt, sizeof(opt));
}

static inline int tcp_sock_set_keepcnt(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPCNT,
				 (char *)&opt, sizeof(opt));
}
#endif /* HAVE_KERNEL_SETSOCKOPT */

#endif /* __LIBCFS_LINUX_NET_H__ */
