// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/ */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/completion.h>
#include <net/sock.h>
#include <linux/sunrpc/addr.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/module.h>
#include <linux/libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

static int   accept_port    = 988;
static int   accept_port_bulk = 988;
static int   accept_backlog = 127;
static int   accept_timeout = 5;

struct listening_socket {
	struct socket	*liss_sock;
	int		liss_port;
	char		liss_iface[IFNAMSIZ];
	struct		list_head liss_list;
	struct		list_head liss_tmp_list;
	atomic_t	refcnt;
};

static LIST_HEAD(socket_list);
static DEFINE_SPINLOCK(socket_lock);
static atomic_t active_sockets = ATOMIC_INIT(0);

static struct {
	int			pta_shutdown;
	struct socket		*pta_sock;
	struct completion	pta_signal;
	struct net		*pta_ns;
	wait_queue_head_t	pta_waitq;
	atomic_t		pta_ready;
	void			(*pta_odata)(struct sock *s);
} lnet_acceptor_state = {
	.pta_shutdown = 1
};

extern void sock_def_readable(struct sock *sk);

int
lnet_acceptor_port(void)
{
	return accept_port;
}
EXPORT_SYMBOL(lnet_acceptor_port);

int
lnet_acceptor_port_bulk(void)
{
	return accept_port_bulk;
}
EXPORT_SYMBOL(lnet_acceptor_port_bulk);

static inline int
lnet_accept_magic(__u32 magic, __u32 constant)
{
	return (magic == constant ||
		magic == __swab32(constant));
}


static char *accept_type = "secure";

module_param_named(accept, accept_type, charp, 0444);
MODULE_PARM_DESC(accept, "Accept connections (secure|all|none)");
module_param(accept_port, int, 0444);
MODULE_PARM_DESC(accept_port, "Acceptor's port for control conns (same on all nodes)");
module_param(accept_port_bulk, int, 0444);
MODULE_PARM_DESC(accept_port_bulk, "Acceptor's port for bulk conns (same on all nodes)");
module_param(accept_backlog, int, 0444);
MODULE_PARM_DESC(accept_backlog, "Acceptor's listen backlog");
module_param(accept_timeout, int, 0644);
MODULE_PARM_DESC(accept_timeout, "Acceptor's timeout (seconds)");

int
lnet_acceptor_timeout(void)
{
	return accept_timeout;
}
EXPORT_SYMBOL(lnet_acceptor_timeout);

void
lnet_connect_console_error(int rc, struct lnet_nid *peer_nid,
			   struct sockaddr *sa)
{
	switch (rc) {
	/* "normal" errors */
	case -ECONNREFUSED:
		CNETERR("Connection to %s at host %pIScp was refused: check that Lustre is running on that node.\n",
			libcfs_nidstr(peer_nid), sa);
		break;
	case -EHOSTUNREACH:
	case -ENETUNREACH:
		CNETERR("Connection to %s at host %pISc was unreachable: the network or that node may be down, or Lustre may be misconfigured.\n",
			libcfs_nidstr(peer_nid), sa);
		break;
	case -ETIMEDOUT:
		CNETERR("Connection to %s at host %pIScp took too long: that node may be hung or experiencing high load.\n",
			libcfs_nidstr(peer_nid), sa);
		break;
	case -ECONNRESET:
		LCONSOLE_ERROR("Connection to %s at host %pIScp was reset: is it running a compatible version of Lustre and is %s one of its NIDs?\n",
			       libcfs_nidstr(peer_nid), sa,
			       libcfs_nidstr(peer_nid));
		break;
	case -EPROTO:
		LCONSOLE_ERROR("Protocol error connecting to %s at host %pIScp: is it running a compatible version of Lustre?\n",
			       libcfs_nidstr(peer_nid), sa);
		break;
	case -EADDRINUSE:
		LCONSOLE_ERROR("No privileged ports available to connect to %s at host %pIScp\n",
			       libcfs_nidstr(peer_nid), sa);
		break;
	default:
		LCONSOLE_ERROR("Unexpected error %d connecting to %s at host %pIScp\n",
			       rc, libcfs_nidstr(peer_nid), sa);
		break;
	}
}
EXPORT_SYMBOL(lnet_connect_console_error);

static void lnet_acceptor_ready(struct sock *sk)
{
	rmb();
	lnet_acceptor_state.pta_odata(sk);

	atomic_set(&lnet_acceptor_state.pta_ready, 1);
	wake_up_interruptible(&lnet_acceptor_state.pta_waitq);
}

static int lnet_acceptor_add_socket(const char *iface, struct sockaddr *addr,
			     int ifindex, struct net *ni_net_ns, int port)
{
	struct listening_socket *lsock;
	int rc;
	char ip_str[INET6_ADDRSTRLEN];


#ifndef HAVE_SOCK_CREATE_KERN_USE_NET
	if (atomic_read(&active_sockets))
		return 0;
#endif

	if (addr == NULL)
		return -EINVAL;
	if (port <= 0 || port > USHRT_MAX)
		return -EINVAL;
	if (strlen(iface) >= IFNAMSIZ)
		return -EINVAL;

	lsock = kmalloc(sizeof(*lsock), GFP_KERNEL);
	if (!lsock)
		return -ENOMEM;

	lsock->liss_sock = lnet_sock_listen(port, accept_backlog,
					    ni_net_ns, addr, ifindex);

	if (IS_ERR(lsock->liss_sock)) {
		rc = PTR_ERR(lsock->liss_sock);
		return rc;
	}

	strscpy(lsock->liss_iface, iface, IFNAMSIZ);
	lsock->liss_port = port;

	/* Setup socket callback properly */
	lnet_acceptor_state.pta_odata = lsock->liss_sock->sk->sk_data_ready;
	lsock->liss_sock->sk->sk_data_ready = lnet_acceptor_ready;

	spin_lock(&socket_lock);
	atomic_set(&lsock->refcnt, 1);
	list_add_tail(&lsock->liss_list, &socket_list);
	atomic_inc(&active_sockets);
	spin_unlock(&socket_lock);

	wmb();
	atomic_set(&lnet_acceptor_state.pta_ready, 1);

	switch (addr->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *addr4 =
			(const struct sockaddr_in *)addr;
		snprintf(ip_str, sizeof(ip_str), "%pI4", &addr4->sin_addr);
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *addr6 =
			(const struct sockaddr_in6 *)addr;
		snprintf(ip_str, sizeof(ip_str), "%pI6", &addr6->sin6_addr);
		break;
	}
	}
	CDEBUG(D_NET, "Added socket on %s:%d (IP: %s)\n", iface, port, ip_str);


	if (!lnet_acceptor_state.pta_shutdown)
		wake_up(&lnet_acceptor_state.pta_waitq);
	return 0;
}

static void lnet_acceptor_remove_socket(const char *iface, int port)
{
	struct listening_socket *lsock, *tmp, *to_free = NULL;
	bool found = false;

	spin_lock(&socket_lock);
	list_for_each_entry_safe(lsock, tmp, &socket_list, liss_list) {
		if (strcmp(lsock->liss_iface, iface) == 0 &&
		    port == lsock->liss_port) {
			list_del(&lsock->liss_list);
			atomic_dec(&active_sockets);

			if (lsock->liss_sock->sk)
				lsock->liss_sock->sk->sk_data_ready =
					lnet_acceptor_state.pta_odata;

			if (atomic_dec_and_test(&lsock->refcnt)) {
				/* Defer release to avoid sleeping under
				   spinlock */
				to_free = lsock;
			}

			CDEBUG(D_NET, "Removed socket on %s\n", iface);
			found = true;
			break;
		}
	}
	spin_unlock(&socket_lock);

	if (to_free) {
		sock_release(to_free->liss_sock);
		kfree(to_free);
	}

	if (!found)
		CERROR("Interface %s not found\n", iface);
}

int lnet_acceptor_add_sockets(const char *iface, struct sockaddr *addr,
			      int ifindex, struct net *ni_net_ns)
{
	int rc;

	rc = lnet_acceptor_add_socket(iface, addr, ifindex, ni_net_ns,
				      accept_port);

	if (!rc && accept_port_bulk != accept_port) {
		rc = lnet_acceptor_add_socket(iface, addr, ifindex, ni_net_ns,
					      accept_port_bulk);
		if (rc)
			lnet_acceptor_remove_socket(iface, accept_port);
	}
	return rc;
}
EXPORT_SYMBOL(lnet_acceptor_add_sockets);

void lnet_acceptor_remove_sockets(const char *iface)
{
	lnet_acceptor_remove_socket(iface, accept_port);

	if (accept_port_bulk != accept_port)
		lnet_acceptor_remove_socket(iface, accept_port_bulk);
}
EXPORT_SYMBOL(lnet_acceptor_remove_sockets);

struct socket *
lnet_connect(struct lnet_nid *peer_nid, int interface,
	     struct sockaddr *peeraddr, struct net *ns,
	     bool control)
{
	struct lnet_acceptor_connreq cr1;
	struct lnet_acceptor_connreq_v2 cr2;
	void *cr;
	int crsize;
	struct socket *sock;
	struct sockaddr_storage destaddr;
	int rc;
	int port;

	BUILD_BUG_ON(sizeof(cr) > 16); /* not too big to be on the stack */

	LASSERT(peeraddr->sa_family == AF_INET ||
		peeraddr->sa_family == AF_INET6);
	rpc_copy_addr((struct sockaddr *)&destaddr, peeraddr);
	if (control)
		rpc_set_port((struct sockaddr *)&destaddr,
			     lnet_acceptor_port());
	else
		rpc_set_port((struct sockaddr *)&destaddr,
			     lnet_acceptor_port_bulk());

	for (port = LNET_ACCEPTOR_MAX_RESERVED_PORT;
	     port >= LNET_ACCEPTOR_MIN_RESERVED_PORT;
	     --port) {
		/* Iterate through reserved ports. */
		sock = lnet_sock_connect(interface, port,
					 (struct sockaddr *)&destaddr, ns);
		if (IS_ERR(sock)) {
			rc = PTR_ERR(sock);
			if (rc == -EADDRINUSE || rc == -EADDRNOTAVAIL)
				continue;
			goto failed;
		}

		BUILD_BUG_ON(LNET_PROTO_ACCEPTOR_VERSION != 1);

		if (nid_is_nid4(peer_nid)) {
			cr1.acr_magic   = LNET_PROTO_ACCEPTOR_MAGIC;
			cr1.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
			cr1.acr_nid     = lnet_nid_to_nid4(peer_nid);
			cr = &cr1;
			crsize = sizeof(cr1);

			if (the_lnet.ln_testprotocompat) {
				/* single-shot proto check */
				if (test_and_clear_bit(
					    2, &the_lnet.ln_testprotocompat))
					cr1.acr_version++;
				if (test_and_clear_bit(
					    3, &the_lnet.ln_testprotocompat))
					cr1.acr_magic = LNET_PROTO_MAGIC;
			}

		} else {
			cr2.acr_magic	= LNET_PROTO_ACCEPTOR_MAGIC;
			cr2.acr_version	= LNET_PROTO_ACCEPTOR_VERSION_16;
			cr2.acr_nid	= *peer_nid;
			cr = &cr2;
			crsize = sizeof(cr2);
		}

		rc = lnet_sock_write(sock, cr, crsize, accept_timeout);
		if (rc != 0)
			goto failed_sock;

		return sock;
	}

	rc = -EADDRINUSE;
	goto failed;

failed_sock:
	sock_release(sock);
failed:
	lnet_connect_console_error(rc, peer_nid, peeraddr);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL(lnet_connect);

static int
lnet_accept(struct socket *sock, __u32 magic)
{
	struct lnet_acceptor_connreq cr;
	struct lnet_acceptor_connreq_v2 cr2;
	struct lnet_nid nid;
	struct sockaddr_storage peer;
	int peer_version;
	int rc;
	int flip;
	struct lnet_ni *ni;
	char *str;

	LASSERT(sizeof(cr) <= 16);		/* not too big for the stack */

	rc = lnet_sock_getaddr(sock, true, &peer);
	if (rc != 0) {
		CERROR("Can't determine new connection's address\n");
		return rc;
	}

	if (!lnet_accept_magic(magic, LNET_PROTO_ACCEPTOR_MAGIC)) {

		if (lnet_accept_magic(magic, LNET_PROTO_MAGIC)) {
			/* future version compatibility!
			 * When LNET unifies protocols over all LNDs, the first
			 * thing sent will be a version query.	I send back
			 * LNET_PROTO_ACCEPTOR_MAGIC to tell her I'm "old" */

			memset(&cr, 0, sizeof(cr));
			cr.acr_magic = LNET_PROTO_ACCEPTOR_MAGIC;
			cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
			rc = lnet_sock_write(sock, &cr, sizeof(cr),
					       accept_timeout);

			if (rc != 0)
				CERROR("Error sending magic+version in response to LNET magic from %pISc: %d\n",
				       &peer, rc);
			return -EPROTO;
		}

		if (lnet_accept_magic(magic, LNET_PROTO_TCP_MAGIC))
			str = "'old' socknal/tcpnal";
		else
			str = "unrecognised";

		LCONSOLE_ERROR("Refusing connection from %pISc magic %08x: %s acceptor protocol\n",
			       &peer, magic, str);
		return -EPROTO;
	}

	flip = (magic != LNET_PROTO_ACCEPTOR_MAGIC);

	rc = lnet_sock_read(sock, &cr.acr_version,
			      sizeof(cr.acr_version),
			      accept_timeout);
	if (rc != 0) {
		CERROR("Error %d reading connection request version from %pISc\n",
		       rc, &peer);
		return -EIO;
	}

	if (flip)
		__swab32s(&cr.acr_version);

	switch (cr.acr_version) {
	default:
		/* future version compatibility!
		 * An acceptor-specific protocol rev will first send a version
		 * query.  I send back my current version to tell her I'm
		 * "old". */
		peer_version = cr.acr_version;

		memset(&cr, 0, sizeof(cr));
		cr.acr_magic = LNET_PROTO_ACCEPTOR_MAGIC;
		cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;

		rc = lnet_sock_write(sock, &cr, sizeof(cr),
				       accept_timeout);

		if (rc != 0)
			CERROR("Error sending magic+version in response to version %d from %pISc: %d\n",
			       peer_version, &peer, rc);
		return -EPROTO;

	case LNET_PROTO_ACCEPTOR_VERSION:

		rc = lnet_sock_read(sock, &cr.acr_nid,
				    sizeof(cr) -
				    offsetof(struct lnet_acceptor_connreq,
					     acr_nid),
				    accept_timeout);
		if (rc)
			break;
		if (flip)
			__swab64s(&cr.acr_nid);

		lnet_nid4_to_nid(cr.acr_nid, &nid);
		break;

	case LNET_PROTO_ACCEPTOR_VERSION_16:
		rc = lnet_sock_read(sock, &cr2.acr_nid,
				    sizeof(cr2) -
				    offsetof(struct lnet_acceptor_connreq_v2,
					     acr_nid),
				    accept_timeout);
		if (rc)
			break;
		nid = cr2.acr_nid;
		break;
	}
	if (rc != 0) {
		CERROR("Error %d reading connection request from %pISc\n",
		       rc, &peer);
		return -EIO;
	}

	ni = lnet_nid_to_ni_addref(&nid);
	if (ni == NULL ||               /* no matching net */
	    !nid_same(&ni->ni_nid, &nid)) {
		/* right NET, wrong NID! */
		if (ni != NULL)
			lnet_ni_decref(ni);
		LCONSOLE_ERROR("Refusing connection from %pISc for %s: No matching NI\n",
			       &peer, libcfs_nidstr(&nid));
		return -EPERM;
	}

	if (ni->ni_net->net_lnd->lnd_accept == NULL) {
		/* This catches a request for the loopback LND */
		lnet_ni_decref(ni);
		LCONSOLE_ERROR("Refusing connection from %pISc for %s: NI doesn not accept IP connections\n",
			       &peer, libcfs_nidstr(&nid));
		return -EPERM;
	}

	CDEBUG(D_NET, "Accept %s from %pI4h\n", libcfs_nidstr(&nid), &peer);

	rc = ni->ni_net->net_lnd->lnd_accept(ni, sock);

	lnet_ni_decref(ni);
	return rc;
}

static int
lnet_acceptor(void *arg)
{
	struct socket  *newsock = NULL;
	__u32 magic;
	struct sockaddr_storage peer;
	int secure = (int)((uintptr_t)arg);
	struct listening_socket *lsock, *tmp;
	int rc = 0;
	LIST_HEAD(copy_list);

	LASSERT(lnet_acceptor_state.pta_sock == NULL);

	init_waitqueue_head(&lnet_acceptor_state.pta_waitq);

	/* set init status and unblock parent */
	lnet_acceptor_state.pta_shutdown = rc;
	complete(&lnet_acceptor_state.pta_signal);

	while (!lnet_acceptor_state.pta_shutdown) {
		wait_event_interruptible(lnet_acceptor_state.pta_waitq,
				lnet_acceptor_state.pta_shutdown ||
				atomic_read(&lnet_acceptor_state.pta_ready));

		if (!atomic_read(&active_sockets))
			continue;
		if (!atomic_read(&lnet_acceptor_state.pta_ready))
			continue;
		atomic_set(&lnet_acceptor_state.pta_ready, 0);

		spin_lock(&socket_lock);
		list_for_each_entry(lsock, &socket_list, liss_list) {
			if (lsock->liss_sock &&
			    atomic_read(&lsock->refcnt) > 0) {
				atomic_inc(&lsock->refcnt);
				list_add_tail(&lsock->liss_tmp_list,
					      &copy_list);
			}
		}
		spin_unlock(&socket_lock);

		list_for_each_entry_safe(lsock, tmp, &copy_list,
					 liss_tmp_list) {
			list_del_init(&lsock->liss_tmp_list);
			rc = kernel_accept(lsock->liss_sock, &newsock,
					   SOCK_NONBLOCK);
			if (rc != 0) {
				if (rc != -EAGAIN) {
					CWARN("Accept error %d: pausing...\n",
					      rc);
					schedule_timeout_uninterruptible(
					cfs_time_seconds(1));
				}
				if (atomic_dec_and_test(&lsock->refcnt)) {
					/* publish restore before release */
					if (lsock->liss_sock && lsock->liss_sock->sk) {
						WRITE_ONCE(lsock->liss_sock->sk->sk_data_ready,
							   lnet_acceptor_state.pta_odata);
						smp_wmb();
					}
					sock_release(lsock->liss_sock);
					kfree(lsock);
				}
				continue;
			}
			/* make sure we call lnet_sock_accept() again,
			   until it fails */
			atomic_set(&lnet_acceptor_state.pta_ready, 1);

			CDEBUG(D_NET, "Accepted connection on %s:%d\n",
			       lsock->liss_iface, lsock->liss_port);

			rc = lnet_sock_getaddr(newsock, true, &peer);
			if (rc != 0) {
				CERROR("Can't determine new connection's address\n");
				goto failed;
			}

			if (secure &&
			    rpc_get_port((struct sockaddr *)&peer) >
					 LNET_ACCEPTOR_MAX_RESERVED_PORT) {
				CERROR("Refusing connection from %pIScp: insecure port.\n",
				       &peer);
				goto failed;
			}

			rc = lnet_sock_read(newsock, &magic, sizeof(magic),
					    accept_timeout);
			if (rc != 0) {
				CERROR("Error %d reading connection request from %pISc\n",
				       rc, &peer);
				goto failed;
			}

			rc = lnet_accept(newsock, magic);
			if (rc != 0)
				goto failed;

			if (atomic_dec_and_test(&lsock->refcnt)) {
				/* publish restore before release */
				if (lsock->liss_sock && lsock->liss_sock->sk) {
					WRITE_ONCE(lsock->liss_sock->sk->sk_data_ready,
						   lnet_acceptor_state.pta_odata);
					smp_wmb();
				}
				sock_release(lsock->liss_sock);
				kfree(lsock);
			}
			continue;

failed:
			if (newsock) {
				sock_release(newsock);
				newsock = NULL;
			}
			if (atomic_dec_and_test(&lsock->refcnt)) {
				/* publish restore before release */
				if (lsock->liss_sock && lsock->liss_sock->sk) {
					WRITE_ONCE(lsock->liss_sock->sk->sk_data_ready,
						   lnet_acceptor_state.pta_odata);
					smp_wmb();
				}
				sock_release(lsock->liss_sock);
				kfree(lsock);
			}
		}
	}

	INIT_LIST_HEAD(&copy_list);

	spin_lock(&socket_lock);
	list_for_each_entry_safe(lsock, tmp, &socket_list, liss_list) {
		list_del(&lsock->liss_list);
		atomic_dec(&active_sockets);

		if (lsock->liss_sock->sk)
			lsock->liss_sock->sk->sk_data_ready =
				lnet_acceptor_state.pta_odata;

		if (atomic_dec_and_test(&lsock->refcnt)) 
			list_add_tail(&lsock->liss_tmp_list, &copy_list);
	}
	spin_unlock(&socket_lock);

	/* Now safely free all lsocks outside lock */
	list_for_each_entry_safe(lsock, tmp, &copy_list, liss_tmp_list) {
		list_del_init(&lsock->liss_tmp_list);
		sock_release(lsock->liss_sock);
		kfree(lsock);
	}

	CDEBUG(D_NET, "Acceptor stopping\n");
	complete(&lnet_acceptor_state.pta_signal);
	return 0;
}

static inline int
accept2secure(const char *acc, long *sec)
{
	if (!strcmp(acc, "secure")) {
		*sec = 1;
		return 1;
	} else if (!strcmp(acc, "all")) {
		*sec = 0;
		return 1;
	} else if (!strcmp(acc, "none")) {
		return 0;
	} else {
		LCONSOLE_ERROR("Can't parse 'accept=\"%s\"'\n", acc);
		return -EINVAL;
	}
}

int
lnet_acceptor_start(void)
{
	struct task_struct *task;
	int  rc;
	long rc2;
	long secure;

	/* if acceptor is already running return immediately */
	if (!lnet_acceptor_state.pta_shutdown)
		return 0;

	LASSERT(lnet_acceptor_state.pta_sock == NULL);

	init_completion(&lnet_acceptor_state.pta_signal);
	rc = accept2secure(accept_type, &secure);
	if (rc <= 0)
		return rc;

	if (lnet_count_acceptor_nets() == 0)  /* not required */
		return 0;
	if (current->nsproxy && current->nsproxy->net_ns)
		lnet_acceptor_state.pta_ns = current->nsproxy->net_ns;
	else
		lnet_acceptor_state.pta_ns = &init_net;
	task = kthread_run(lnet_acceptor, (void *)(uintptr_t)secure,
			   "acceptor_%03ld", secure);
	if (IS_ERR(task)) {
		rc2 = PTR_ERR(task);
		CERROR("Can't start acceptor thread: %ld\n", rc2);
		return -ESRCH;
	}

	/* wait for acceptor to startup */
	wait_for_completion(&lnet_acceptor_state.pta_signal);

	if (!lnet_acceptor_state.pta_shutdown)
		/* started OK */
		return 0;

	LASSERT(lnet_acceptor_state.pta_sock == NULL);

	return -ENETDOWN;
}

void
lnet_acceptor_stop(void)
{
	if (lnet_acceptor_state.pta_shutdown) /* not running */
		return;

	/* If still required, return immediately */
	if (the_lnet.ln_refcount && lnet_count_acceptor_nets() > 0)
		return;

	lnet_acceptor_state.pta_shutdown = 1;
	wake_up(&lnet_acceptor_state.pta_waitq);

	/* block until acceptor signals exit */
	wait_for_completion(&lnet_acceptor_state.pta_signal);
}
