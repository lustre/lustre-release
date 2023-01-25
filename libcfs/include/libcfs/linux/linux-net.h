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

#include <net/netlink.h>
#include <net/genetlink.h>

#ifndef HAVE_NLA_STRDUP
char *nla_strdup(const struct nlattr *nla, gfp_t flags);
#endif /* !HAVE_NLA_STRDUP */

#ifdef HAVE_NLA_STRLCPY
#define nla_strscpy	nla_strlcpy
#endif /* HAVE_NLA_STRLCPY */

#ifndef HAVE_NL_PARSE_WITH_EXT_ACK

#define NL_SET_BAD_ATTR(extack, attr)

/* this can be increased when necessary - don't expose to userland */
#define NETLINK_MAX_COOKIE_LEN  20

/**
 * struct netlink_ext_ack - netlink extended ACK report struct
 * @_msg: message string to report - don't access directly, use
 *      %NL_SET_ERR_MSG
 * @bad_attr: attribute with error
 * @cookie: cookie data to return to userspace (for success)
 * @cookie_len: actual cookie data length
 */
struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	u8 cookie[NETLINK_MAX_COOKIE_LEN];
	u8 cookie_len;
};

#define GENL_SET_ERR_MSG(info, msg) NL_SET_ERR_MSG(NULL, msg)

static inline int cfs_nla_parse(struct nlattr **tb, int maxtype,
				const struct nlattr *head, int len,
				const struct nla_policy *policy,
				struct netlink_ext_ack *extack)
{
	return nla_parse(tb, maxtype, head, len, policy);
}

static inline int cfs_nla_parse_nested(struct nlattr *tb[], int maxtype,
				       const struct nlattr *nla,
				       const struct nla_policy *policy,
				       struct netlink_ext_ack *extack)
{
	return nla_parse_nested(tb, maxtype, nla, policy);
}

#else /* !HAVE_NL_PARSE_WITH_EXT_ACK */

#define cfs_nla_parse_nested    nla_parse_nested
#define cfs_nla_parse           nla_parse

#endif

#ifndef HAVE_GENL_DUMPIT_INFO
struct cfs_genl_dumpit_info {
	const struct genl_family *family;
	const struct genl_ops *ops;
	struct nlattr **attrs;
};

static inline const struct cfs_genl_dumpit_info *
lnet_genl_dumpit_info(struct netlink_callback *cb)
{
	return (const struct cfs_genl_dumpit_info *)cb->args[1];
}
#else
#define cfs_genl_dumpit_info	genl_dumpit_info

static inline const struct cfs_genl_dumpit_info *
lnet_genl_dumpit_info(struct netlink_callback *cb)
{
	return (const struct cfs_genl_dumpit_info *)genl_dumpit_info(cb);
}
#endif /* HAVE_GENL_DUMPIT_INFO */

#ifdef HAVE_KERNEL_SETSOCKOPT

#include <net/tcp.h>

#if !defined(HAVE_TCP_SOCK_SET_QUICKACK)
static inline void tcp_sock_set_quickack(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	kernel_setsockopt(sock, SOL_TCP, TCP_QUICKACK,
			  (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_QUICKACK */

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
#endif /* HAVE_KERNEL_SETSOCKOPT */

#endif /* __LIBCFS_LINUX_NET_H__ */
