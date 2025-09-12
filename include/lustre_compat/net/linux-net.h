/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_NET_H__
#define __LIBCFS_LINUX_NET_H__

#include <linux/netdevice.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#ifndef HAVE_NETDEV_CMD_TO_NAME
static inline const char *netdev_cmd_to_name(unsigned long cmd)
{
#define N(val)                                                 \
	case NETDEV_##val:                              \
		return "NETDEV_" __stringify(val);
	switch (cmd) {
	N(UP) N(DOWN) N(REBOOT) N(CHANGE) N(REGISTER) N(UNREGISTER)
	N(CHANGEMTU) N(CHANGEADDR) N(GOING_DOWN) N(CHANGENAME) N(FEAT_CHANGE)
	N(BONDING_FAILOVER) N(PRE_UP) N(PRE_TYPE_CHANGE) N(POST_TYPE_CHANGE)
	N(POST_INIT) N(RELEASE) N(NOTIFY_PEERS) N(JOIN) N(CHANGEUPPER)
	N(RESEND_IGMP) N(PRECHANGEMTU) N(CHANGEINFODATA) N(BONDING_INFO)
	N(PRECHANGEUPPER) N(CHANGELOWERSTATE) N(UDP_TUNNEL_PUSH_INFO)
	N(UDP_TUNNEL_DROP_INFO) N(CHANGE_TX_QUEUE_LEN)
	};
#undef N
	return "UNKNOWN_NETDEV_EVENT";
}
#endif

/* NL_SET_ERR_MSG macros is already defined in kernels
 * 3.10.0-1160 and above. For older kernels (3.10.0-957)
 * where this is not defined we put the message to the
 * system log as a workaround
 */
#ifndef NL_SET_ERR_MSG
#define NL_SET_ERR_MSG(unused, msg) do {              \
       static const char __msg[] = msg;               \
       pr_debug("%s\n", __msg);                       \
} while (0)
#endif

#ifndef NLM_F_DUMP_FILTERED
#define NLM_F_DUMP_FILTERED   0x20    /* Dump was filtered as requested */
#endif

#ifndef HAVE_NLA_STRDUP
char *nla_strdup(const struct nlattr *nla, gfp_t flags);
#endif /* !HAVE_NLA_STRDUP */

#ifdef HAVE_NLA_STRLCPY
#define nla_strscpy	nla_strlcpy
#endif /* HAVE_NLA_STRLCPY */

#ifndef HAVE_NLA_PUT_U64_64BIT
#define nla_put_u64_64bit(skb, type, value, padattr) \
	nla_put_u64(skb, type, value)
#endif

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

#endif /* __LIBCFS_LINUX_NET_H__ */
