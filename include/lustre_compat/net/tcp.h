/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_NET_TCP_H__
#define __LIBCFS_NET_TCP_H__

#include <net/tcp.h>

#ifdef HAVE_KERNEL_SETSOCKOPT

#if !defined(HAVE_TCP_SOCK_SET_QUICKACK)
static inline void tcp_sock_set_quickack(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	kernel_setsockopt(sock, SOL_TCP, TCP_QUICKACK,
			  (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_QUICKACK */

#if !defined(HAVE_TCP_SOCK_SET_KEEPINTVL)
static inline int tcp_sock_set_keepintvl(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL,
				 (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_KEEPINTVL */

#if !defined(HAVE_TCP_SOCK_SET_KEEPCNT)
static inline int tcp_sock_set_keepcnt(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPCNT,
				 (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_KEEPCNT */

#if !defined(HAVE_IP6_SET_PREF)
static inline void ip6_sock_set_addr_preferences(struct sock *sk,
						 unsigned int pref)
{
	kernel_setsockopt(sk->sk_socket, SOL_IPV6, IPV6_ADDR_PREFERENCES,
			  (char *)&pref, sizeof(pref));
}
#endif /* HAVE_IP6_SET_PREF */

#if !defined(HAVE_IP_SET_TOS)
static inline void ip_sock_set_tos(struct sock *sk, int val)
{
	kernel_setsockopt(sk->sk_socket, IPPROTO_IP, IP_TOS,
			  (char *)&val, sizeof(val));
}
#endif /* HAVE_IP_SET_TOS */
#endif /* HAVE_KERNEL_SETSOCKOPT */

#endif /* __LIBCFS_NET_TCP_H__ */
