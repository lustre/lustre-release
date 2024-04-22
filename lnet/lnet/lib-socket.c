// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/ */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/if.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <linux/file.h>
#include <linux/pagemap.h>
/* For sys_open & sys_close */
#include <linux/syscalls.h>
#include <net/sock.h>
#include <linux/inetdevice.h>

#include <libcfs/linux/linux-time.h>
#include <libcfs/linux/linux-net.h>
#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

int
lnet_sock_write(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = cfs_time_seconds(timeout);
	unsigned long then;

	LASSERT(nob > 0);
	/* Caller may pass a zero timeout if she thinks the socket buffer is
	 * empty enough to take the whole message immediately */

	for (;;) {
		struct kvec  iov = {
			.iov_base = buffer,
			.iov_len  = nob
		};
		struct msghdr msg = {
			.msg_flags	= (timeout == 0) ? MSG_DONTWAIT : 0
		};

		if (timeout != 0) {
			struct sock *sk = sock->sk;

			/* Set send timeout to remaining time */
			lock_sock(sk);
			sk->sk_sndtimeo = jiffies_left;
			release_sock(sk);
		}

		then = jiffies;
		rc = kernel_sendmsg(sock, &msg, &iov, 1, nob);
		jiffies_left -= jiffies - then;

		if (rc == nob)
			return 0;

		if (rc < 0)
			return rc;

		if (rc == 0) {
			CERROR("Unexpected zero rc\n");
			return -ECONNABORTED;
		}

		if (jiffies_left <= 0)
			return -EAGAIN;

		buffer = ((char *)buffer) + rc;
		nob -= rc;
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_write);

int
lnet_sock_read(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = cfs_time_seconds(timeout);
	unsigned long then;

	LASSERT(nob > 0);
	LASSERT(jiffies_left > 0);

	for (;;) {
		struct kvec  iov = {
			.iov_base = buffer,
			.iov_len  = nob
		};
		struct msghdr msg = {
			.msg_flags	= 0
		};
		struct sock *sk = sock->sk;

		/* Set receive timeout to remaining time */
		lock_sock(sk);
		sk->sk_rcvtimeo = jiffies_left;
		release_sock(sk);

		then = jiffies;
		rc = kernel_recvmsg(sock, &msg, &iov, 1, nob, 0);
		jiffies_left -= jiffies - then;

		if (rc < 0)
			return rc;

		if (rc == 0)
			return -ECONNRESET;

		buffer = ((char *)buffer) + rc;
		nob -= rc;

		if (nob == 0)
			return 0;

		if (jiffies_left <= 0)
			return -ETIMEDOUT;
	}
}
EXPORT_SYMBOL(lnet_sock_read);

int choose_ipv4_src(__u32 *ret, int interface, __u32 dst_ipaddr, struct net *ns)
{
	struct net_device *dev;
	struct in_device *in_dev;
	int err;
	DECLARE_CONST_IN_IFADDR(ifa);

	rcu_read_lock();
	dev = dev_get_by_index_rcu(ns, interface);
	err = -EINVAL;
	if (!dev || !(dev->flags & IFF_UP))
		goto out;
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev)
		goto out;
	err = -ENOENT;
	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		if (err ||
		    ((dst_ipaddr ^ ntohl(ifa->ifa_local))
		     & ntohl(ifa->ifa_mask)) == 0) {
			/* This address at least as good as what we
			 * already have
			 */
			*ret = ntohl(ifa->ifa_local);
			err = 0;
		}
	}
	endfor_ifa(in_dev);
out:
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(choose_ipv4_src);

static struct socket *
lnet_sock_create(int interface, struct sockaddr *remaddr,
		 int local_port, struct net *ns)
{
	struct socket *sock;
	int rc;
	int family;

	family = AF_INET6;
	if (remaddr)
		family = remaddr->sa_family;
retry:
#ifdef HAVE_SOCK_CREATE_KERN_USE_NET
	rc = sock_create_kern(ns, family, SOCK_STREAM, 0, &sock);
#else
	rc = sock_create_kern(family, SOCK_STREAM, 0, &sock);
#endif
	if (rc == -EAFNOSUPPORT && family == AF_INET6 && !remaddr) {
		family = AF_INET;
		goto retry;
	}

	if (rc) {
		CERROR("Can't create socket: %d\n", rc);
		return ERR_PTR(rc);
	}

	sock->sk->sk_reuseport = 1;

	if (interface >= 0 || local_port != 0) {
		struct sockaddr_storage locaddr = {};

		switch (family) {
		case AF_INET: {
			struct sockaddr_in *sin = (void *)&locaddr;

			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = INADDR_ANY;
			if (interface >= 0 && remaddr) {
				struct sockaddr_in *rem = (void *)remaddr;
				__u32 ip;

				rc = choose_ipv4_src(&ip,
						     interface,
						     ntohl(rem->sin_addr.s_addr),
						     ns);
				if (rc)
					goto failed;
				sin->sin_addr.s_addr = htonl(ip);
			}
			sin->sin_port = htons(local_port);
			break;
		}
#if IS_ENABLED(CONFIG_IPV6)
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (void *)&locaddr;
			int val = 0;

			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = in6addr_any;

			/* Make sure we get both IPv4 and IPv6 connections.
			 * This is the default, but it can be overridden so we
			 * force it back.
			 */
#ifdef HAVE_KERNEL_SETSOCKOPT
			kernel_setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
					  (char *) &val, sizeof(val));
#elif defined(_LINUX_SOCKPTR_H)
			/* sockptr_t was introduced around
			 * v5.8-rc4-1952-ga7b75c5a8c41 and allows a
			 * kernel address to be passed to ->setsockopt
			 */
			if (ipv6_only_sock(sock->sk)) {
				sockptr_t optval = KERNEL_SOCKPTR(&val);

				sock->ops->setsockopt(sock,
						      IPPROTO_IPV6, IPV6_V6ONLY,
						      optval, sizeof(val));
			}
#else
			/* From v5.7-rc6-2614-g5a892ff2facb when
			 * kernel_setsockopt() was removed until
			 * sockptr_t (above) there is no clean way to
			 * pass kernel address to setsockopt.  We could
			 * use get_fs()/set_fs(), but in this particular
			 * situation there is an easier way.  It depends
			 * on the fact that at least for these few
			 * kernels a NULL address to ipv6_setsockopt()
			 * is treated like the address of a zero.
			 */
			if (ipv6_only_sock(sock->sk) && !val) {
				void *optval = NULL;

				sock->ops->setsockopt(sock,
						      IPPROTO_IPV6, IPV6_V6ONLY,
						      optval, sizeof(val));
			}
#endif /* HAVE_KERNEL_SETSOCKOPT */

			if (interface >= 0 && remaddr) {
				struct sockaddr_in6 *rem = (void *)remaddr;

				ipv6_dev_get_saddr(ns,
						   dev_get_by_index(ns,
								    interface),
						   &rem->sin6_addr, 0,
						   &sin6->sin6_addr);
			}
			sin6->sin6_port = htons(local_port);
			break;
		}
#endif /* IS_ENABLED(CONFIG_IPV6) */
		}
		rc = kernel_bind(sock, (struct sockaddr *)&locaddr,
				 sizeof(locaddr));
		if (rc == -EADDRINUSE) {
			CDEBUG(D_NET, "Port %d already in use\n", local_port);
			goto failed;
		}
		if (rc != 0) {
			CERROR("Error trying to bind to %pISc/%d: rc = %d\n",
			       &locaddr, local_port, rc);
			goto failed;
		}
	}
	return sock;

failed:
	sock_release(sock);
	return ERR_PTR(rc);
}

void
lnet_sock_setbuf(struct socket *sock, int txbufsize, int rxbufsize)
{
	struct sock *sk = sock->sk;

	if (txbufsize != 0) {
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		sk->sk_sndbuf = txbufsize;
		sk->sk_write_space(sk);
	}

	if (rxbufsize != 0) {
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
		sk->sk_sndbuf = rxbufsize;
	}
}
EXPORT_SYMBOL(lnet_sock_setbuf);

int
lnet_sock_getaddr(struct socket *sock, bool remote,
		  struct sockaddr_storage *peer)
{
	int rc;
#ifndef HAVE_KERN_SOCK_GETNAME_2ARGS
	int len = sizeof(*peer);
#endif

	if (remote)
		rc = lnet_kernel_getpeername(sock,
					     (struct sockaddr *)peer, &len);
	else
		rc = lnet_kernel_getsockname(sock,
					     (struct sockaddr *)peer, &len);
	if (rc < 0) {
		CERROR("Error %d getting sock %s IP/port\n",
			rc, remote ? "peer" : "local");
		return rc;
	}
	if (peer->ss_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (void *)peer;
		struct sockaddr_in *in = (void *)peer;
		short port = in6->sin6_port;

		if (ipv6_addr_v4mapped(&in6->sin6_addr)) {
			/* Pretend it is a v4 socket */
			memset(in, 0, sizeof(*in));
			in->sin_family = AF_INET;
			in->sin_port = port;
			memcpy(&in->sin_addr, &in6->sin6_addr.s6_addr32[3], 4);
		}
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_getaddr);

void lnet_sock_getbuf(struct socket *sock, int *txbufsize, int *rxbufsize)
{
	if (txbufsize != NULL)
		*txbufsize = sock->sk->sk_sndbuf;

	if (rxbufsize != NULL)
		*rxbufsize = sock->sk->sk_rcvbuf;
}
EXPORT_SYMBOL(lnet_sock_getbuf);

struct socket *
lnet_sock_listen(int local_port, int backlog, struct net *ns)
{
	struct socket *sock;
	int rc;

	sock = lnet_sock_create(-1, NULL, local_port, ns);
	if (IS_ERR(sock)) {
		rc = PTR_ERR(sock);
		if (rc == -EADDRINUSE)
			CERROR("Can't create socket: port %d already in use\n",
			       local_port);
		return ERR_PTR(rc);
	}

	rc = kernel_listen(sock, backlog);
	if (rc == 0)
		return sock;

	CERROR("Can't set listen backlog %d: %d\n", backlog, rc);
	sock_release(sock);
	return ERR_PTR(rc);
}

struct socket *
lnet_sock_connect(int interface, int local_port,
		  struct sockaddr *peeraddr,
		  struct net *ns)
{
	struct socket *sock;
	int rc;

	sock = lnet_sock_create(interface, peeraddr, local_port, ns);
	if (IS_ERR(sock))
		return sock;

	/* Avoid temporary address, they are bad for long-lived
	 * connections such as lustre mounts.
	 * RFC4941, section 3.6 suggests that:
	 *    Individual applications, which have specific
	 *    knowledge about the normal duration of connections,
	 *    MAY override this as appropriate.
	 */
	if (peeraddr->sa_family == PF_INET6)
		ip6_sock_set_addr_preferences(sock->sk,
					      IPV6_PREFER_SRC_PUBLIC);

	rc = kernel_connect(sock, peeraddr, sizeof(struct sockaddr_in6), 0);
	if (rc == 0)
		return sock;

	/* EADDRNOTAVAIL probably means we're already connected to the same
	 * peer/port on the same local port on a differently typed
	 * connection.	Let our caller retry with a different local
	 * port... */

	CDEBUG_LIMIT(rc == -EADDRNOTAVAIL ? D_NET : D_NETERROR,
		     "Error %d connecting %d -> %pIScp\n", rc,
		     local_port, peeraddr);

	sock_release(sock);
	return ERR_PTR(rc);
}

static int lnet_inet4_enumerate(struct net_device *dev, int flags,
				int *nalloc, int nip, int cpt,
				struct lnet_inetdev **dev_list)
{
	struct lnet_inetdev *ifaces = *dev_list;
	struct in_device *in_dev;
	DECLARE_CONST_IN_IFADDR(ifa);

	in_dev = __in_dev_get_rtnl(dev);
	if (!in_dev) {
		CWARN("lnet: Interface %s has no IPv4 status.\n",
		      dev->name);
		return nip;
	}

	in_dev_for_each_ifa_rtnl(ifa, in_dev) {
		if (nip >= *nalloc) {
			struct lnet_inetdev *tmp;

			*nalloc += LNET_INTERFACES_NUM;
			tmp = krealloc(ifaces, *nalloc * sizeof(*tmp),
				       GFP_KERNEL);
			if (!tmp) {
				kfree(ifaces);
				ifaces = NULL;
				return -ENOMEM;
			}
			ifaces = tmp;
		}

		ifaces[nip].li_cpt = cpt;
		ifaces[nip].li_iff_master = !!(flags & IFF_MASTER);
		ifaces[nip].li_size = sizeof(ifa->ifa_local);
		ifaces[nip].li_index = dev->ifindex;
		ifaces[nip].li_ipaddr = ifa->ifa_local;
		ifaces[nip].li_netmask = ntohl(ifa->ifa_mask);
		strscpy(ifaces[nip].li_name, ifa->ifa_label,
		       sizeof(ifaces[nip].li_name));
		nip++;
	}
	endfor_ifa(in_dev);

	*dev_list = ifaces;

	return nip;
}

static int lnet_inet6_enumerate(struct net_device *dev, int flags,
				int *nalloc, int nip, int cpt,
				struct lnet_inetdev **dev_list)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct lnet_inetdev *ifaces = *dev_list;
	const struct inet6_ifaddr *ifa6;
	struct inet6_dev *in6_dev;

	in6_dev = __in6_dev_get(dev);
	if (!in6_dev) {
		CWARN("lnet: Interface %s has no IPv6 status.\n",
		      dev->name);
		return nip;
	}

	list_for_each_entry_rcu(ifa6, &in6_dev->addr_list, if_list) {
		if (ifa6->flags & IFA_F_TEMPORARY)
			continue;

		if (ipv6_addr_type(&ifa6->addr) & IPV6_ADDR_LINKLOCAL)
			continue;

		if (nip >= *nalloc) {
			struct lnet_inetdev *tmp;

			*nalloc += LNET_INTERFACES_NUM;
			tmp = krealloc(ifaces, *nalloc * sizeof(*tmp),
				       GFP_KERNEL);
			if (!tmp) {
				kfree(ifaces);
				ifaces = NULL;
				return -ENOMEM;
			}
			ifaces = tmp;
		}

		ifaces[nip].li_cpt = cpt;
		ifaces[nip].li_iff_master = !!(flags & IFF_MASTER);
		ifaces[nip].li_size = sizeof(struct in6_addr);
		ifaces[nip].li_index = dev->ifindex;
		memcpy(ifaces[nip].li_ipv6addr,
		       &ifa6->addr, sizeof(struct in6_addr));
		strscpy(ifaces[nip].li_name, dev->name,
			sizeof(ifaces[nip].li_name));
		nip++;
		/* As different IPv6 addresses don't have unique
		 * labels, it is safest just to use the first
		 * and ignore the rest.
		 */
		break;
	}

	*dev_list = ifaces;
#endif /* IS_ENABLED(CONFIG_IPV6) */
	return nip;
}

int lnet_inet_enumerate(struct lnet_inetdev **dev_list, struct net *ns,
			bool v6_first)
{
	struct lnet_inetdev *ifaces = NULL;
	struct net_device *dev;
	int nalloc = 0;
	int nip = 0;

	rtnl_lock();
	for_each_netdev(ns, dev) {
		int flags = dev_get_flags(dev);
		int node_id, cpt;
		int count;

		if (flags & IFF_LOOPBACK) /* skip the loopback IF */
			continue;

		if (!(flags & IFF_UP)) {
			CWARN("lnet: Ignoring interface %s: it's down\n",
			      dev->name);
			continue;
		}

		node_id = dev_to_node(&dev->dev);
		cpt = cfs_cpt_of_node(lnet_cpt_table(), node_id);

		if (v6_first) {
			count = lnet_inet6_enumerate(dev, flags, &nalloc, nip,
						     cpt, &ifaces);
			if (count < 0)
				CWARN("lnet: No IPv6 addresses for interface %s.\n",
				      dev->name);
			else
				nip = count;

			count = lnet_inet4_enumerate(dev, flags, &nalloc, nip,
						     cpt, &ifaces);
			if (count < 0)
				CWARN("lnet: No IPv4 addresses for interface %s.\n",
				      dev->name);
			else
				nip = count;
		} else {
			count = lnet_inet4_enumerate(dev, flags, &nalloc, nip,
						     cpt, &ifaces);
			if (count < 0)
				CWARN("lnet: No IPv4 addresses for interface %s.\n",
				      dev->name);
			else
				nip = count;

			count = lnet_inet6_enumerate(dev, flags, &nalloc, nip,
						     cpt, &ifaces);
			if (count < 0)
				CWARN("lnet: No IPv6 addresses for interface %s.\n",
				      dev->name);
			else
				nip = count;
		}
	}
	rtnl_unlock();

	if (nip == 0) {
		CERROR("lnet: Can't find any usable interfaces, rc = -ENOENT\n");
		nip = -ENOENT;
	}

	*dev_list = ifaces;
	return nip;
}
EXPORT_SYMBOL(lnet_inet_enumerate);
