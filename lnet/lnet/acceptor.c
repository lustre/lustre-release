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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/completion.h>
#include <net/sock.h>
#include <lnet/lib-lnet.h>
#include <linux/sunrpc/addr.h>

static int   accept_port    = 988;
static int   accept_backlog = 127;
static int   accept_timeout = 5;

static struct {
	int			pta_shutdown;
	struct socket		*pta_sock;
	struct completion	pta_signal;
	struct net		*pta_ns;
	wait_queue_head_t	pta_waitq;
	atomic_t		pta_ready;
#ifdef HAVE_SK_DATA_READY_ONE_ARG
	void			(*pta_odata)(struct sock *);
#else
	void			(*pta_odata)(struct sock *, int);
#endif
} lnet_acceptor_state = {
	.pta_shutdown = 1
};

int
lnet_acceptor_port(void)
{
	return accept_port;
}

static inline int
lnet_accept_magic(__u32 magic, __u32 constant)
{
	return (magic == constant ||
		magic == __swab32(constant));
}

EXPORT_SYMBOL(lnet_acceptor_port);

static char *accept_type = "secure";

module_param_named(accept, accept_type, charp, 0444);
MODULE_PARM_DESC(accept, "Accept connections (secure|all|none)");
module_param(accept_port, int, 0444);
MODULE_PARM_DESC(accept_port, "Acceptor's port (same on all nodes)");
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
lnet_connect_console_error (int rc, lnet_nid_t peer_nid,
			    struct sockaddr *sa)
{
	switch (rc) {
	/* "normal" errors */
	case -ECONNREFUSED:
		CNETERR("Connection to %s at host %pISp was refused: check that Lustre is running on that node.\n",
			libcfs_nid2str(peer_nid), sa);
		break;
	case -EHOSTUNREACH:
	case -ENETUNREACH:
		CNETERR("Connection to %s at host %pIS was unreachable: the network or that node may be down, or Lustre may be misconfigured.\n",
			libcfs_nid2str(peer_nid), sa);
		break;
	case -ETIMEDOUT:
		CNETERR("Connection to %s at host %pISp took too long: that node may be hung or experiencing high load.\n",
			libcfs_nid2str(peer_nid), sa);
		break;
	case -ECONNRESET:
		LCONSOLE_ERROR_MSG(0x11b,
				   "Connection to %s at host %pISp was reset: is it running a compatible version of Lustre and is %s one of its NIDs?\n",
				   libcfs_nid2str(peer_nid), sa,
				   libcfs_nid2str(peer_nid));
		break;
	case -EPROTO:
		LCONSOLE_ERROR_MSG(0x11c,
				   "Protocol error connecting to %s at host %pISp: is it running a compatible version of Lustre?\n",
				   libcfs_nid2str(peer_nid), sa);
		break;
	case -EADDRINUSE:
		LCONSOLE_ERROR_MSG(0x11d,
				   "No privileged ports available to connect to %s at host %pISp\n",
				   libcfs_nid2str(peer_nid), sa);
		break;
	default:
		LCONSOLE_ERROR_MSG(0x11e,
				   "Unexpected error %d connecting to %s at host %pISp\n",
				   rc, libcfs_nid2str(peer_nid), sa);
		break;
	}
}
EXPORT_SYMBOL(lnet_connect_console_error);

struct socket *
lnet_connect(lnet_nid_t peer_nid, int interface, struct sockaddr *peeraddr,
	     struct net *ns)
{
	struct lnet_acceptor_connreq cr;
	struct socket		*sock;
	int			rc;
	int			port;

	BUILD_BUG_ON(sizeof(cr) > 16); /* not too big to be on the stack */

	LASSERT(peeraddr->sa_family == AF_INET ||
		peeraddr->sa_family == AF_INET6);

	for (port = LNET_ACCEPTOR_MAX_RESERVED_PORT;
	     port >= LNET_ACCEPTOR_MIN_RESERVED_PORT;
	     --port) {
		/* Iterate through reserved ports. */
		sock = lnet_sock_connect(interface, port, peeraddr, ns);
		if (IS_ERR(sock)) {
			rc = PTR_ERR(sock);
			if (rc == -EADDRINUSE || rc == -EADDRNOTAVAIL)
				continue;
			goto failed;
		}

		BUILD_BUG_ON(LNET_PROTO_ACCEPTOR_VERSION != 1);

		cr.acr_magic   = LNET_PROTO_ACCEPTOR_MAGIC;
		cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;
		cr.acr_nid     = peer_nid;

		if (the_lnet.ln_testprotocompat) {
			/* single-shot proto check */
			if (test_and_clear_bit(2, &the_lnet.ln_testprotocompat))
				cr.acr_version++;
			if (test_and_clear_bit(3, &the_lnet.ln_testprotocompat))
				cr.acr_magic = LNET_PROTO_MAGIC;
		}

		rc = lnet_sock_write(sock, &cr, sizeof(cr),
				       accept_timeout);
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
	struct sockaddr_storage peer;
	int			rc;
	int			flip;
	struct lnet_ni *ni;
	char		       *str;

	LASSERT(sizeof(cr) <= 16);		/* not too big for the stack */

	rc = lnet_sock_getaddr(sock, true, &peer);
	LASSERT(rc == 0);			/* we succeeded before */

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
				CERROR("Error sending magic+version in response to LNET magic from %pIS: %d\n",
				       &peer, rc);
			return -EPROTO;
		}

		if (lnet_accept_magic(magic, LNET_PROTO_TCP_MAGIC))
			str = "'old' socknal/tcpnal";
		else
			str = "unrecognised";

		LCONSOLE_ERROR_MSG(0x11f, "Refusing connection from %pIS"
				   " magic %08x: %s acceptor protocol\n",
				   &peer, magic, str);
		return -EPROTO;
	}

	flip = (magic != LNET_PROTO_ACCEPTOR_MAGIC);

	rc = lnet_sock_read(sock, &cr.acr_version,
			      sizeof(cr.acr_version),
			      accept_timeout);
	if (rc != 0) {
		CERROR("Error %d reading connection request version from %pIS\n",
		       rc, &peer);
		return -EIO;
	}

	if (flip)
		__swab32s(&cr.acr_version);

	if (cr.acr_version != LNET_PROTO_ACCEPTOR_VERSION) {
		/* future version compatibility!
		 * An acceptor-specific protocol rev will first send a version
		 * query.  I send back my current version to tell her I'm
		 * "old". */
		int peer_version = cr.acr_version;

		memset(&cr, 0, sizeof(cr));
		cr.acr_magic = LNET_PROTO_ACCEPTOR_MAGIC;
		cr.acr_version = LNET_PROTO_ACCEPTOR_VERSION;

		rc = lnet_sock_write(sock, &cr, sizeof(cr),
				       accept_timeout);

		if (rc != 0)
			CERROR("Error sending magic+version in response to version %d from %pIS: %d\n",
			       peer_version, &peer, rc);
		return -EPROTO;
	}

	rc = lnet_sock_read(sock, &cr.acr_nid,
			      sizeof(cr) -
			      offsetof(struct lnet_acceptor_connreq, acr_nid),
			      accept_timeout);
	if (rc != 0) {
		CERROR("Error %d reading connection request from %pIS\n",
		       rc, &peer);
		return -EIO;
	}

	if (flip)
		__swab64s(&cr.acr_nid);

	ni = lnet_nid2ni_addref(cr.acr_nid);
	if (ni == NULL ||               /* no matching net */
	    ni->ni_nid != cr.acr_nid) { /* right NET, wrong NID! */
		if (ni != NULL)
			lnet_ni_decref(ni);
		LCONSOLE_ERROR_MSG(0x120,
				   "Refusing connection from %pIS for %s: No matching NI\n",
				   &peer, libcfs_nid2str(cr.acr_nid));
		return -EPERM;
	}

	if (ni->ni_net->net_lnd->lnd_accept == NULL) {
		/* This catches a request for the loopback LND */
		lnet_ni_decref(ni);
		LCONSOLE_ERROR_MSG(0x121,
				   "Refusing connection from %pIS for %s: NI doesn not accept IP connections\n",
				  &peer, libcfs_nid2str(cr.acr_nid));
		return -EPERM;
	}

	CDEBUG(D_NET, "Accept %s from %pI4h\n",
	       libcfs_nid2str(cr.acr_nid), &peer);

	rc = ni->ni_net->net_lnd->lnd_accept(ni, sock);

	lnet_ni_decref(ni);
	return rc;
}

#ifdef HAVE_SK_DATA_READY_ONE_ARG
static void lnet_acceptor_ready(struct sock *sk)
#else
static void lnet_acceptor_ready(struct sock *sk, int len)
#endif
{
	/* Ensure pta_odata has actually been set before calling it */
	rmb();
#ifdef HAVE_SK_DATA_READY_ONE_ARG
	lnet_acceptor_state.pta_odata(sk);
#else
	lnet_acceptor_state.pta_odata(sk, 0);
#endif

	atomic_set(&lnet_acceptor_state.pta_ready, 1);
	wake_up(&lnet_acceptor_state.pta_waitq);
}

static int
lnet_acceptor(void *arg)
{
	struct socket  *newsock;
	int	       rc;
	__u32	       magic;
	struct sockaddr_storage peer;
	int	       secure = (int)((uintptr_t)arg);

	LASSERT(lnet_acceptor_state.pta_sock == NULL);

	lnet_acceptor_state.pta_sock =
		lnet_sock_listen(accept_port, accept_backlog,
				 lnet_acceptor_state.pta_ns);
	if (IS_ERR(lnet_acceptor_state.pta_sock)) {
		rc = PTR_ERR(lnet_acceptor_state.pta_sock);
		if (rc == -EADDRINUSE)
			LCONSOLE_ERROR_MSG(0x122, "Can't start acceptor on port"
					   " %d: port already in use\n",
					   accept_port);
		else
			LCONSOLE_ERROR_MSG(0x123, "Can't start acceptor on port "
					   "%d: unexpected error %d\n",
					   accept_port, rc);

		lnet_acceptor_state.pta_sock = NULL;
	} else {
		rc = 0;
		LCONSOLE(0, "Accept %s, port %d\n", accept_type, accept_port);
		init_waitqueue_head(&lnet_acceptor_state.pta_waitq);
		lnet_acceptor_state.pta_odata =
			lnet_acceptor_state.pta_sock->sk->sk_data_ready;
		/* ensure pta_odata gets set before there is any chance of
		 * lnet_accept_ready() trying to read it.
		 */
		wmb();
		lnet_acceptor_state.pta_sock->sk->sk_data_ready =
			lnet_acceptor_ready;
		atomic_set(&lnet_acceptor_state.pta_ready, 1);
	}

	/* set init status and unblock parent */
	lnet_acceptor_state.pta_shutdown = rc;
	complete(&lnet_acceptor_state.pta_signal);

	if (rc != 0)
		return rc;

	while (!lnet_acceptor_state.pta_shutdown) {

		wait_event_idle(lnet_acceptor_state.pta_waitq,
				lnet_acceptor_state.pta_shutdown ||
				atomic_read(&lnet_acceptor_state.pta_ready));
		if (!atomic_read(&lnet_acceptor_state.pta_ready))
			continue;
		atomic_set(&lnet_acceptor_state.pta_ready, 0);
		rc = kernel_accept(lnet_acceptor_state.pta_sock, &newsock,
				   SOCK_NONBLOCK);
		if (rc != 0) {
			if (rc != -EAGAIN) {
				CWARN("Accept error %d: pausing...\n", rc);
				schedule_timeout_uninterruptible(
					cfs_time_seconds(1));
			}
			continue;
		}

		/* make sure we call lnet_sock_accept() again, until it fails */
		atomic_set(&lnet_acceptor_state.pta_ready, 1);

		rc = lnet_sock_getaddr(newsock, true, &peer);
		if (rc != 0) {
			CERROR("Can't determine new connection's address\n");
			goto failed;
		}

		if (secure &&
		    rpc_get_port((struct sockaddr *)&peer) >
		    LNET_ACCEPTOR_MAX_RESERVED_PORT) {
			CERROR("Refusing connection from %pISp: insecure port.\n",
			       &peer);
			goto failed;
		}

		rc = lnet_sock_read(newsock, &magic, sizeof(magic),
				      accept_timeout);
		if (rc != 0) {
			CERROR("Error %d reading connection request from %pIS\n",
			       rc, &peer);
			goto failed;
		}

		rc = lnet_accept(newsock, magic);
		if (rc != 0)
			goto failed;

		continue;

failed:
		sock_release(newsock);
	}

	lnet_acceptor_state.pta_sock->sk->sk_data_ready =
		lnet_acceptor_state.pta_odata;
	sock_release(lnet_acceptor_state.pta_sock);
	lnet_acceptor_state.pta_sock = NULL;

	CDEBUG(D_NET, "Acceptor stopping\n");

	/* unblock lnet_acceptor_stop() */
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
		LCONSOLE_ERROR_MSG(0x124, "Can't parse 'accept=\"%s\"'\n",
				   acc);
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

	if (!lnet_acceptor_state.pta_shutdown) {
		/* started OK */
		LASSERT(lnet_acceptor_state.pta_sock != NULL);
		return 0;
	}

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
