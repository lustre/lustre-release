// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Zach Brown <zab@zabbo.net>
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include <linux/ethtool.h>
#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/sunrpc/addr.h>
#include <net/addrconf.h>
#include "socklnd.h"

static const struct lnet_lnd the_ksocklnd;
struct ksock_nal_data ksocknal_data;

static int ksocknal_ip2index(struct sockaddr *addr, struct lnet_ni *ni,
			     int *dev_status)
{
	struct net_device *dev;
	int ret = -1;
	DECLARE_CONST_IN_IFADDR(ifa);

	*dev_status = -1;

	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		return ret;

	rcu_read_lock();
	for_each_netdev_rcu(ni->ni_net_ns, dev) {
		int flags = dev_get_flags(dev);
		struct in_device *in_dev;

		if (flags & IFF_LOOPBACK) /* skip the loopback IF */
			continue;

		if (!(flags & IFF_UP))
			continue;

		switch (addr->sa_family) {
		case AF_INET:
			in_dev = __in_dev_get_rcu(dev);
			if (!in_dev)
				continue;

			in_dev_for_each_ifa_rcu(ifa, in_dev) {
				if (ifa->ifa_local ==
				    ((struct sockaddr_in *)addr)->sin_addr.s_addr)
					ret = dev->ifindex;
			}
			endfor_ifa(in_dev);
			break;
#if IS_ENABLED(CONFIG_IPV6)
		case AF_INET6: {
			struct inet6_dev *in6_dev;
			const struct inet6_ifaddr *ifa6;
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)addr;

			in6_dev = __in6_dev_get(dev);
			if (!in6_dev)
				continue;

			list_for_each_entry_rcu(ifa6, &in6_dev->addr_list, if_list) {
				if (ipv6_addr_cmp(&ifa6->addr,
						 &addr6->sin6_addr) == 0)
					ret = dev->ifindex;
			}
			break;
			}
#endif /* IS_ENABLED(CONFIG_IPV6) */
		}
		if (ret >= 0)
			break;
	}

	rcu_read_unlock();
	if (ret >= 0)
		*dev_status = 1;

	if ((ret == -1) ||
	    ((dev->reg_state == NETREG_UNREGISTERING) ||
	     ((dev->operstate != IF_OPER_UP) &&
	      (dev->operstate != IF_OPER_UNKNOWN))) ||
	    (lnet_get_link_status(dev) == 0))
		*dev_status = 0;

	return ret;
}

static struct ksock_conn_cb *
ksocknal_create_conn_cb(struct sockaddr *addr)
{
	struct ksock_conn_cb *conn_cb;

	LIBCFS_ALLOC(conn_cb, sizeof(*conn_cb));
	if (!conn_cb)
		return NULL;

	refcount_set(&conn_cb->ksnr_refcount, 1);
	conn_cb->ksnr_peer = NULL;
	conn_cb->ksnr_retry_interval = 0;         /* OK to connect at any time */
	rpc_copy_addr((struct sockaddr *)&conn_cb->ksnr_addr, addr);
	rpc_set_port((struct sockaddr *)&conn_cb->ksnr_addr,
		     rpc_get_port(addr));
	conn_cb->ksnr_scheduled = 0;
	conn_cb->ksnr_connecting = 0;
	conn_cb->ksnr_connected = 0;
	conn_cb->ksnr_deleted = 0;
	conn_cb->ksnr_conn_count = 0;
	conn_cb->ksnr_ctrl_conn_count = 0;
	conn_cb->ksnr_blki_conn_count = 0;
	conn_cb->ksnr_blko_conn_count = 0;
	conn_cb->ksnr_max_conns = 0;
	conn_cb->ksnr_busy_retry_count = 0;

	return conn_cb;
}

void
ksocknal_destroy_conn_cb(struct ksock_conn_cb *conn_cb)
{
	LASSERT(refcount_read(&conn_cb->ksnr_refcount) == 0);

	if (conn_cb->ksnr_peer)
		ksocknal_peer_decref(conn_cb->ksnr_peer);

	LIBCFS_FREE(conn_cb, sizeof(*conn_cb));
}

static struct ksock_peer_ni *
ksocknal_create_peer(struct lnet_ni *ni, struct lnet_processid *id)
{
	int cpt = lnet_nid2cpt(&id->nid, ni);
	struct ksock_net *net = ni->ni_data;
	struct ksock_peer_ni *peer_ni;

	LASSERT(!LNET_NID_IS_ANY(&id->nid));
	LASSERT(id->pid != LNET_PID_ANY);
	LASSERT(!in_interrupt());

	if (!atomic_inc_unless_negative(&net->ksnn_npeers)) {
		CERROR("Can't create peer_ni: network shutdown\n");
		return ERR_PTR(-ESHUTDOWN);
	}

	LIBCFS_CPT_ALLOC(peer_ni, lnet_cpt_table(), cpt, sizeof(*peer_ni));
	if (!peer_ni) {
		atomic_dec(&net->ksnn_npeers);
		return ERR_PTR(-ENOMEM);
	}

	peer_ni->ksnp_ni = ni;
	peer_ni->ksnp_id = *id;
	refcount_set(&peer_ni->ksnp_refcount, 1); /* 1 ref for caller */
	peer_ni->ksnp_closing = 0;
	peer_ni->ksnp_accepting = 0;
	peer_ni->ksnp_proto = NULL;
	peer_ni->ksnp_last_alive = 0;
	peer_ni->ksnp_zc_next_cookie = SOCKNAL_KEEPALIVE_PING + 1;
	peer_ni->ksnp_conn_cb = NULL;

	INIT_LIST_HEAD(&peer_ni->ksnp_conns);
	INIT_LIST_HEAD(&peer_ni->ksnp_tx_queue);
	INIT_LIST_HEAD(&peer_ni->ksnp_zc_req_list);
	spin_lock_init(&peer_ni->ksnp_lock);

	return peer_ni;
}

void
ksocknal_destroy_peer(struct ksock_peer_ni *peer_ni)
{
	struct ksock_net *net = peer_ni->ksnp_ni->ni_data;

	CDEBUG(D_NET, "peer_ni %s %p deleted\n",
	       libcfs_idstr(&peer_ni->ksnp_id), peer_ni);

	LASSERT(refcount_read(&peer_ni->ksnp_refcount) == 0);
	LASSERT(peer_ni->ksnp_accepting == 0);
	LASSERT(list_empty(&peer_ni->ksnp_conns));
	LASSERT(peer_ni->ksnp_conn_cb == NULL);
	LASSERT(list_empty(&peer_ni->ksnp_tx_queue));
	LASSERT(list_empty(&peer_ni->ksnp_zc_req_list));

	LIBCFS_FREE(peer_ni, sizeof(*peer_ni));

	/* NB a peer_ni's connections and conn_cb keep a reference on their
	 * peer_ni until they are destroyed, so we can be assured that _all_
	 * state to do with this peer_ni has been cleaned up when its refcount
	 * drops to zero.
	 */
	if (atomic_dec_and_test(&net->ksnn_npeers))
		wake_up_var(&net->ksnn_npeers);
}

struct ksock_peer_ni *
ksocknal_find_peer_locked(struct lnet_ni *ni, struct lnet_processid *id)
{
	struct ksock_peer_ni *peer_ni;
	unsigned long hash = nidhash(&id->nid);

	hash_for_each_possible(ksocknal_data.ksnd_peers, peer_ni,
			       ksnp_list, hash) {
		LASSERT(!peer_ni->ksnp_closing);

		if (peer_ni->ksnp_ni != ni)
			continue;

		if (!nid_same(&peer_ni->ksnp_id.nid, &id->nid) ||
		    peer_ni->ksnp_id.pid != id->pid)
			continue;

		CDEBUG(D_NET, "got peer_ni [%p] -> %s (%d)\n",
		       peer_ni, libcfs_idstr(id),
		       refcount_read(&peer_ni->ksnp_refcount));
		return peer_ni;
	}
	return NULL;
}

struct ksock_peer_ni *
ksocknal_find_peer(struct lnet_ni *ni, struct lnet_processid *id)
{
	struct ksock_peer_ni *peer_ni;

	read_lock(&ksocknal_data.ksnd_global_lock);
	peer_ni = ksocknal_find_peer_locked(ni, id);
	if (peer_ni != NULL)			/* +1 ref for caller? */
		ksocknal_peer_addref(peer_ni);
	read_unlock(&ksocknal_data.ksnd_global_lock);

	return peer_ni;
}

static void
ksocknal_unlink_peer_locked(struct ksock_peer_ni *peer_ni)
{
	LASSERT(list_empty(&peer_ni->ksnp_conns));
	LASSERT(peer_ni->ksnp_conn_cb == NULL);
	LASSERT(!peer_ni->ksnp_closing);
	peer_ni->ksnp_closing = 1;
	hlist_del(&peer_ni->ksnp_list);
	/* lose peerlist's ref */
	ksocknal_peer_decref(peer_ni);
}


static void
ksocknal_dump_peer_debug_info(struct ksock_peer_ni *peer_ni)
{
	struct ksock_conn *conn;
	struct list_head *ctmp;
	struct list_head *txtmp;
	int ccount = 0;
	int txcount = 0;

	list_for_each(ctmp, &peer_ni->ksnp_conns) {
		conn = list_entry(ctmp, struct ksock_conn, ksnc_list);

		if (!list_empty(&conn->ksnc_tx_queue))
			list_for_each(txtmp, &conn->ksnc_tx_queue) txcount++;

		CDEBUG(D_CONSOLE, "Conn %d [type, closing, crefcnt, srefcnt]: %d, %d, %d, %d\n",
		       ccount,
		       conn->ksnc_type,
		       conn->ksnc_closing,
		       refcount_read(&conn->ksnc_conn_refcount),
		       refcount_read(&conn->ksnc_sock_refcount));
		CDEBUG(D_CONSOLE, "Conn %d rx [scheduled, ready, state]: %d, %d, %d\n",
		       ccount,
		       conn->ksnc_rx_scheduled,
		       conn->ksnc_rx_ready,
		       conn->ksnc_rx_state);
		CDEBUG(D_CONSOLE, "Conn %d tx [txqcnt, scheduled, last_post, ready, deadline]: %d, %d, %lld, %d, %lld\n",
		       ccount,
		       txcount,
		       conn->ksnc_tx_scheduled,
		       conn->ksnc_tx_last_post,
		       conn->ksnc_rx_ready,
		       conn->ksnc_rx_deadline);

		if (conn->ksnc_scheduler)
			CDEBUG(D_CONSOLE, "Conn %d sched [nconns, cpt]: %d, %d\n",
			       ccount,
			       conn->ksnc_scheduler->kss_nconns,
			       conn->ksnc_scheduler->kss_cpt);

		txcount = 0;
		ccount++;
	}
}

static int
ksocknal_get_peer_info(struct lnet_ni *ni, int index,
		       struct lnet_processid *id, __u32 *myip, __u32 *peer_ip,
		       int *port, int *conn_count, int *share_count)
{
	struct ksock_peer_ni *peer_ni;
	struct ksock_conn_cb *conn_cb;
	int i;
	int rc = -ENOENT;
	struct ksock_net *net;

	read_lock(&ksocknal_data.ksnd_global_lock);

	hash_for_each(ksocknal_data.ksnd_peers, i, peer_ni, ksnp_list) {

		if (peer_ni->ksnp_ni != ni)
			continue;
		if (index-- > 0)
			continue;

		*id = peer_ni->ksnp_id;
		conn_cb = peer_ni->ksnp_conn_cb;
		if (conn_cb == NULL) {
			*myip = 0;
			*peer_ip = 0;
			*port = 0;
			*conn_count = 0;
			*share_count = 0;
			rc = 0;
		} else {
			ksocknal_dump_peer_debug_info(peer_ni);

			if (conn_cb->ksnr_addr.ss_family == AF_INET) {
				struct sockaddr_in *sa =
					(void *)&conn_cb->ksnr_addr;
				net = ni->ni_data;
				rc = choose_ipv4_src(myip,
						     net->ksnn_interface.ksni_index,
						     ntohl(sa->sin_addr.s_addr),
						     ni->ni_net_ns);
				*peer_ip = ntohl(sa->sin_addr.s_addr);
				*port = ntohs(sa->sin_port);

			} else {
				*myip = 0xFFFFFFFF;
				*peer_ip = 0xFFFFFFFF;
				*port = 0;
				rc = -ENOTSUPP;
			}
			*conn_count = conn_cb->ksnr_conn_count;
			*share_count = 1;
		}
		break;
	}
	read_unlock(&ksocknal_data.ksnd_global_lock);
	return rc;
}

static unsigned int
ksocknal_get_conns_per_peer(struct ksock_peer_ni *peer_ni)
{
	struct lnet_ni *ni = peer_ni->ksnp_ni;
	struct lnet_ioctl_config_socklnd_tunables *tunables;

	LASSERT(ni);

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_sock;

	return tunables->lnd_conns_per_peer;
}

static void
ksocknal_incr_conn_count(struct ksock_conn_cb *conn_cb,
			 int type)
{
	conn_cb->ksnr_conn_count++;

	/* check if all connections of the given type got created */
	switch (type) {
	case SOCKLND_CONN_CONTROL:
		conn_cb->ksnr_ctrl_conn_count++;
		/* there's a single control connection per peer,
		 * two in case of loopback
		 */
		conn_cb->ksnr_connected |= BIT(type);
		break;
	case SOCKLND_CONN_BULK_IN:
		conn_cb->ksnr_blki_conn_count++;
		if (conn_cb->ksnr_blki_conn_count >= conn_cb->ksnr_max_conns)
			conn_cb->ksnr_connected |= BIT(type);
		break;
	case SOCKLND_CONN_BULK_OUT:
		conn_cb->ksnr_blko_conn_count++;
		if (conn_cb->ksnr_blko_conn_count >= conn_cb->ksnr_max_conns)
			conn_cb->ksnr_connected |= BIT(type);
		break;
	case SOCKLND_CONN_ANY:
		if (conn_cb->ksnr_conn_count >= conn_cb->ksnr_max_conns)
			conn_cb->ksnr_connected |= BIT(type);
		break;
	default:
		LBUG();
		break;
	}

	CDEBUG(D_NET, "Add conn type %d, ksnr_connected %x ksnr_max_conns %d\n",
	       type, conn_cb->ksnr_connected, conn_cb->ksnr_max_conns);
}


static void
ksocknal_decr_conn_count(struct ksock_conn_cb *conn_cb,
			 int type)
{
	conn_cb->ksnr_conn_count--;

	/* check if all connections of the given type got created */
	switch (type) {
	case SOCKLND_CONN_CONTROL:
		conn_cb->ksnr_ctrl_conn_count--;
		/* there's a single control connection per peer,
		 * two in case of loopback
		 */
		if (conn_cb->ksnr_ctrl_conn_count == 0)
			conn_cb->ksnr_connected &= ~BIT(type);
		break;
	case SOCKLND_CONN_BULK_IN:
		conn_cb->ksnr_blki_conn_count--;
		if (conn_cb->ksnr_blki_conn_count == 0)
			conn_cb->ksnr_connected &= ~BIT(type);
		break;
	case SOCKLND_CONN_BULK_OUT:
		conn_cb->ksnr_blko_conn_count--;
		if (conn_cb->ksnr_blko_conn_count == 0)
			conn_cb->ksnr_connected &= ~BIT(type);
		break;
	case SOCKLND_CONN_ANY:
		if (conn_cb->ksnr_conn_count == 0)
			conn_cb->ksnr_connected &= ~BIT(type);
		break;
	default:
		LBUG();
		break;
	}

	CDEBUG(D_NET, "Del conn type %d, ksnr_connected %x ksnr_max_conns %d\n",
	       type, conn_cb->ksnr_connected, conn_cb->ksnr_max_conns);
}

static void
ksocknal_associate_cb_conn_locked(struct ksock_conn_cb *conn_cb,
				  struct ksock_conn *conn)
{
	int type = conn->ksnc_type;

	conn->ksnc_conn_cb = conn_cb;
	ksocknal_conn_cb_addref(conn_cb);
	ksocknal_incr_conn_count(conn_cb, type);

	/* Successful connection => further attempts can
	 * proceed immediately
	 */
	conn_cb->ksnr_retry_interval = 0;
}

static void
ksocknal_add_conn_cb_locked(struct ksock_peer_ni *peer_ni,
			    struct ksock_conn_cb *conn_cb)
{
	struct ksock_conn *conn;
	struct ksock_net *net = peer_ni->ksnp_ni->ni_data;

	LASSERT(!peer_ni->ksnp_closing);
	LASSERT(!conn_cb->ksnr_peer);
	LASSERT(!conn_cb->ksnr_scheduled);
	LASSERT(!conn_cb->ksnr_connecting);
	LASSERT(conn_cb->ksnr_connected == 0);

	conn_cb->ksnr_peer = peer_ni;
	ksocknal_peer_addref(peer_ni);

	/* peer_ni's route list takes over my ref on 'route' */
	peer_ni->ksnp_conn_cb = conn_cb;
	net->ksnn_interface.ksni_nroutes++;

	list_for_each_entry(conn, &peer_ni->ksnp_conns, ksnc_list) {
		if (!rpc_cmp_addr((struct sockaddr *)&conn->ksnc_peeraddr,
				  (struct sockaddr *)&conn_cb->ksnr_addr))
			continue;
		CDEBUG(D_NET, "call ksocknal_associate_cb_conn_locked\n");
		ksocknal_associate_cb_conn_locked(conn_cb, conn);
		/* keep going (typed conns) */
	}
}

static void
ksocknal_del_conn_cb_locked(struct ksock_conn_cb *conn_cb)
{
	struct ksock_peer_ni *peer_ni = conn_cb->ksnr_peer;
	struct ksock_conn *conn;
	struct ksock_conn *cnxt;
	struct ksock_net *net;

	LASSERT(!conn_cb->ksnr_deleted);

	/* Close associated conns */
	list_for_each_entry_safe(conn, cnxt, &peer_ni->ksnp_conns, ksnc_list) {
		if (conn->ksnc_conn_cb != conn_cb)
			continue;

		ksocknal_close_conn_locked(conn, 0);
	}

	net = (struct ksock_net *)(peer_ni->ksnp_ni->ni_data);
	net->ksnn_interface.ksni_nroutes--;
	LASSERT(net->ksnn_interface.ksni_nroutes >= 0);

	conn_cb->ksnr_deleted = 1;
	ksocknal_conn_cb_decref(conn_cb);		/* drop peer_ni's ref */
	peer_ni->ksnp_conn_cb = NULL;

	if (list_empty(&peer_ni->ksnp_conns)) {
		/* I've just removed the last route to a peer_ni with no active
		 * connections
		 */
		ksocknal_unlink_peer_locked(peer_ni);
	}
}

unsigned int
ksocknal_get_conn_count_by_type(struct ksock_conn_cb *conn_cb,
				int type)
{
	unsigned int count = 0;

	switch (type) {
	case SOCKLND_CONN_CONTROL:
		count = conn_cb->ksnr_ctrl_conn_count;
		break;
	case SOCKLND_CONN_BULK_IN:
		count = conn_cb->ksnr_blki_conn_count;
		break;
	case SOCKLND_CONN_BULK_OUT:
		count = conn_cb->ksnr_blko_conn_count;
		break;
	case SOCKLND_CONN_ANY:
		count = conn_cb->ksnr_conn_count;
		break;
	default:
		LBUG();
		break;
	}

	return count;
}

int
ksocknal_add_peer(struct lnet_ni *ni, struct lnet_processid *id,
		  struct sockaddr *addr)
{
	struct ksock_peer_ni *peer_ni;
	struct ksock_peer_ni *peer2;
	struct ksock_conn_cb *conn_cb;

	if (LNET_NID_IS_ANY(&id->nid) ||
	    id->pid == LNET_PID_ANY)
		return (-EINVAL);

	/* Have a brand new peer_ni ready... */
	peer_ni = ksocknal_create_peer(ni, id);
	if (IS_ERR(peer_ni))
		return PTR_ERR(peer_ni);

	conn_cb = ksocknal_create_conn_cb(addr);
	if (!conn_cb) {
		ksocknal_peer_decref(peer_ni);
		return -ENOMEM;
	}

	write_lock_bh(&ksocknal_data.ksnd_global_lock);

	/* always called with a ref on ni, so shutdown can't have started */
	LASSERT(atomic_read(&((struct ksock_net *)ni->ni_data)->ksnn_npeers)
		>= 0);

	peer2 = ksocknal_find_peer_locked(ni, id);
	if (peer2 != NULL) {
		ksocknal_peer_decref(peer_ni);
		peer_ni = peer2;
	} else {
		/* peer_ni table takes my ref on peer_ni */
		hash_add(ksocknal_data.ksnd_peers, &peer_ni->ksnp_list,
			 nidhash(&id->nid));
	}

	if (peer_ni->ksnp_conn_cb) {
		ksocknal_conn_cb_decref(conn_cb);
	} else {
		/* Remember conns_per_peer setting at the time
		 * of connection initiation. It will define the
		 * max number of conns per type for this conn_cb
		 * while it's in use.
		 */
		conn_cb->ksnr_max_conns = ksocknal_get_conns_per_peer(peer_ni);
		ksocknal_add_conn_cb_locked(peer_ni, conn_cb);
	}

	write_unlock_bh(&ksocknal_data.ksnd_global_lock);

	return 0;
}

static void
ksocknal_del_peer_locked(struct ksock_peer_ni *peer_ni)
{
	struct ksock_conn *conn;
	struct ksock_conn *cnxt;
	struct ksock_conn_cb *conn_cb;

	LASSERT(!peer_ni->ksnp_closing);

	/* Extra ref prevents peer_ni disappearing until I'm done with it */
	ksocknal_peer_addref(peer_ni);
	conn_cb = peer_ni->ksnp_conn_cb;
	if (conn_cb)
		ksocknal_del_conn_cb_locked(conn_cb);

	list_for_each_entry_safe(conn, cnxt, &peer_ni->ksnp_conns,
				 ksnc_list)
		ksocknal_close_conn_locked(conn, 0);

	ksocknal_peer_decref(peer_ni);
	/* NB peer_ni unlinks itself when last conn/conn_cb is removed */
}

static int
ksocknal_del_peer(struct lnet_ni *ni, struct lnet_processid *id)
{
	LIST_HEAD(zombies);
	struct hlist_node *pnxt;
	struct ksock_peer_ni *peer_ni;
	int lo;
	int hi;
	int i;
	int rc = -ENOENT;

	write_lock_bh(&ksocknal_data.ksnd_global_lock);

	if (id && !LNET_NID_IS_ANY(&id->nid)) {
		lo = hash_min(nidhash(&id->nid),
			      HASH_BITS(ksocknal_data.ksnd_peers));
		hi = lo;
	} else {
		lo = 0;
		hi = HASH_SIZE(ksocknal_data.ksnd_peers) - 1;
	}

	for (i = lo; i <= hi; i++) {
		hlist_for_each_entry_safe(peer_ni, pnxt,
					  &ksocknal_data.ksnd_peers[i],
					  ksnp_list) {
			if (peer_ni->ksnp_ni != ni)
				continue;

			if (!((!id || LNET_NID_IS_ANY(&id->nid) ||
			       nid_same(&peer_ni->ksnp_id.nid, &id->nid)) &&
			      (!id || id->pid == LNET_PID_ANY ||
			       peer_ni->ksnp_id.pid == id->pid)))
				continue;

			ksocknal_peer_addref(peer_ni);	/* a ref for me... */

			ksocknal_del_peer_locked(peer_ni);

			if (peer_ni->ksnp_closing &&
			    !list_empty(&peer_ni->ksnp_tx_queue)) {
				LASSERT(list_empty(&peer_ni->ksnp_conns));
				LASSERT(peer_ni->ksnp_conn_cb == NULL);

				list_splice_init(&peer_ni->ksnp_tx_queue,
						 &zombies);
			}

			ksocknal_peer_decref(peer_ni);	/* ...till here */

			rc = 0;				/* matched! */
		}
	}

	write_unlock_bh(&ksocknal_data.ksnd_global_lock);

	ksocknal_txlist_done(ni, &zombies, -ENETDOWN);

	return rc;
}

static struct ksock_conn *
ksocknal_get_conn_by_idx(struct lnet_ni *ni, int index)
{
	struct ksock_peer_ni *peer_ni;
	struct ksock_conn *conn;
	int i;

	read_lock(&ksocknal_data.ksnd_global_lock);

	hash_for_each(ksocknal_data.ksnd_peers, i, peer_ni, ksnp_list) {
		LASSERT(!peer_ni->ksnp_closing);

		if (peer_ni->ksnp_ni != ni)
			continue;

		list_for_each_entry(conn, &peer_ni->ksnp_conns,
				    ksnc_list) {
			if (index-- > 0)
				continue;

			ksocknal_conn_addref(conn);
			read_unlock(&ksocknal_data.ksnd_global_lock);
			return conn;
		}
	}

	read_unlock(&ksocknal_data.ksnd_global_lock);
	return NULL;
}

static struct ksock_sched *
ksocknal_choose_scheduler_locked(unsigned int cpt)
{
	struct ksock_sched *sched = ksocknal_data.ksnd_schedulers[cpt];
	int i;

	if (sched->kss_nthreads == 0) {
		cfs_percpt_for_each(sched, i, ksocknal_data.ksnd_schedulers) {
			if (sched->kss_nthreads > 0) {
				CDEBUG(D_NET, "scheduler[%d] has no threads. selected scheduler[%d]\n",
				       cpt, sched->kss_cpt);
				return sched;
			}
		}
		return NULL;
	}

	return sched;
}

int
ksocknal_accept(struct lnet_ni *ni, struct socket *sock)
{
	struct ksock_connreq *cr;
	int rc;
	struct sockaddr_storage peer;

	rc = lnet_sock_getaddr(sock, true, &peer);
	if (rc != 0) {
		CERROR("Can't determine new connection's address\n");
		return rc;
	}

	LIBCFS_ALLOC(cr, sizeof(*cr));
	if (cr == NULL) {
		LCONSOLE_ERROR("Dropping connection request from %pISc: memory exhausted\n",
			       &peer);
		return -ENOMEM;
	}

	lnet_ni_addref(ni);
	cr->ksncr_ni   = ni;
	cr->ksncr_sock = sock;

	spin_lock_bh(&ksocknal_data.ksnd_connd_lock);

	list_add_tail(&cr->ksncr_list, &ksocknal_data.ksnd_connd_connreqs);
	wake_up(&ksocknal_data.ksnd_connd_waitq);

	spin_unlock_bh(&ksocknal_data.ksnd_connd_lock);
	return 0;
}

static const struct ln_key_list ksocknal_tunables_keys = {
	.lkl_maxattr			= LNET_NET_SOCKLND_TUNABLES_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_SOCKLND_TUNABLES_ATTR_CONNS_PER_PEER]  = {
			.lkp_value	= "conns_per_peer",
			.lkp_data_type	= NLA_U16
		},
		[LNET_NET_SOCKLND_TUNABLES_ATTR_LND_TIMEOUT]	= {
			.lkp_value	= "timeout",
			.lkp_data_type	= NLA_U32
		},
		[LNET_NET_SOCKLND_TUNABLES_ATTR_LND_TOS] = {
			.lkp_value	= "tos",
			.lkp_data_type	= NLA_S16,
		},
	},
};

static int
ksocknal_nl_get(int cmd, struct sk_buff *msg, int type, void *data)
{
	struct lnet_lnd_tunables *tun;
	struct lnet_ni *ni = data;

	if (!ni || !msg)
		return -EINVAL;

	 if (cmd != LNET_CMD_NETS || type != LNET_NET_LOCAL_NI_ATTR_LND_TUNABLES)
		return -EOPNOTSUPP;

	tun = &ni->ni_lnd_tunables;
	nla_put_u16(msg, LNET_NET_SOCKLND_TUNABLES_ATTR_CONNS_PER_PEER,
		    tun->lnd_tun_u.lnd_sock.lnd_conns_per_peer);
	nla_put_u32(msg, LNET_NET_SOCKLND_TUNABLES_ATTR_LND_TIMEOUT,
		    ksocknal_timeout());
	nla_put_s16(msg, LNET_NET_SOCKLND_TUNABLES_ATTR_LND_TOS,
		    tun->lnd_tun_u.lnd_sock.lnd_tos);

	return 0;
}

static inline void
ksocknal_nl_set_default(int cmd, int type, void *data)
{
	struct lnet_lnd_tunables *tunables = data;
	struct lnet_ioctl_config_socklnd_tunables *lt;
	struct lnet_ioctl_config_socklnd_tunables *df;

	lt = &tunables->lnd_tun_u.lnd_sock;
	df = &ksock_default_tunables;
	switch (type) {
	case LNET_NET_SOCKLND_TUNABLES_ATTR_CONNS_PER_PEER:
		lt->lnd_conns_per_peer = df->lnd_conns_per_peer;
		break;
	case LNET_NET_SOCKLND_TUNABLES_ATTR_LND_TIMEOUT:
		lt->lnd_timeout = df->lnd_timeout;
		fallthrough;
	default:
		break;
	}
}

static int
ksocknal_nl_set(int cmd, struct nlattr *attr, int type, void *data)
{
	struct lnet_lnd_tunables *tunables = data;
	int rc = 0;
	s64 num;

	if (cmd != LNET_CMD_NETS)
		return -EOPNOTSUPP;

	if (!attr) {
		ksocknal_nl_set_default(cmd, type, data);
		return 0;
	}

	if (nla_type(attr) != LN_SCALAR_ATTR_INT_VALUE)
		return -EINVAL;

	switch (type) {
	case LNET_NET_SOCKLND_TUNABLES_ATTR_CONNS_PER_PEER:
		/* value values are 1 to 127. Zero mean calculate the value */
		num = nla_get_s64(attr);
		if (num > -1 && num < 128)
			tunables->lnd_tun_u.lnd_sock.lnd_conns_per_peer = num;
		else
			rc = -ERANGE;
		break;
	case LNET_NET_SOCKLND_TUNABLES_ATTR_LND_TIMEOUT:
		num = nla_get_s64(attr);
		tunables->lnd_tun_u.lnd_sock.lnd_timeout = num;
		break;
	case LNET_NET_SOCKLND_TUNABLES_ATTR_LND_TOS:
		num = nla_get_s64(attr);
		clamp_t(s64, num, -1, 0xff);
		tunables->lnd_tun_u.lnd_sock.lnd_tos = num;
		fallthrough;
	default:
		break;
	}

	return rc;
}

static int
ksocknal_connecting(struct ksock_conn_cb *conn_cb, struct sockaddr *sa)
{
	if (conn_cb &&
	    rpc_cmp_addr((struct sockaddr *)&conn_cb->ksnr_addr, sa))
		return conn_cb->ksnr_connecting;
	return 0;
}

int
ksocknal_create_conn(struct lnet_ni *ni, struct ksock_conn_cb *conn_cb,
		     struct socket *sock, int type)
{
	rwlock_t *global_lock = &ksocknal_data.ksnd_global_lock;
	LIST_HEAD(zombies);
	struct lnet_processid peerid;
	u64 incarnation;
	struct ksock_conn *conn;
	struct ksock_conn *conn2;
	struct ksock_peer_ni *peer_ni = NULL;
	struct ksock_peer_ni *peer2;
	struct ksock_sched *sched;
	struct ksock_hello_msg *hello;
	int cpt;
	struct ksock_tx *tx;
	struct ksock_tx *txtmp;
	int rc;
	int rc2;
	int active;
	int num_dup = 0;
	char *warn = NULL;

	active = (conn_cb != NULL);

	LASSERT(active == (type != SOCKLND_CONN_NONE));

	LIBCFS_ALLOC(conn, sizeof(*conn));
	if (conn == NULL) {
		rc = -ENOMEM;
		goto failed_0;
	}

	conn->ksnc_peer = NULL;
	conn->ksnc_conn_cb = NULL;
	conn->ksnc_sock = sock;
	/* 2 ref, 1 for conn, another extra ref prevents socket
	 * being closed before establishment of connection
	 */
	refcount_set(&conn->ksnc_sock_refcount, 2);
	conn->ksnc_type = type;
	ksocknal_lib_save_callback(sock, conn);
	refcount_set(&conn->ksnc_conn_refcount, 1); /* 1 ref for me */

	conn->ksnc_rx_ready = 0;
	conn->ksnc_rx_scheduled = 0;

	INIT_LIST_HEAD(&conn->ksnc_tx_queue);
	conn->ksnc_tx_ready = 0;
	conn->ksnc_tx_scheduled = 0;
	conn->ksnc_tx_carrier = NULL;
	atomic_set(&conn->ksnc_tx_nob, 0);

	LIBCFS_ALLOC(hello, offsetof(struct ksock_hello_msg,
				     kshm_ips[LNET_INTERFACES_NUM]));
	if (hello == NULL) {
		rc = -ENOMEM;
		goto failed_1;
	}

	/* stash conn's local and remote addrs */
	rc = ksocknal_lib_get_conn_addrs(conn);
	if (rc != 0)
		goto failed_1;

	/* Find out/confirm peer_ni's NID and connection type and get the
	 * vector of interfaces she's willing to let me connect to.
	 * Passive connections use the listener timeout since the peer_ni sends
	 * eagerly
	 */
	if (active) {
		struct sockaddr_in *psa = (void *)&conn->ksnc_peeraddr;

		peer_ni = conn_cb->ksnr_peer;
		LASSERT(ni == peer_ni->ksnp_ni);

		/* Active connection sends HELLO eagerly */
		hello->kshm_nips = 0;
		peerid = peer_ni->ksnp_id;

		write_lock_bh(global_lock);
		conn->ksnc_proto = peer_ni->ksnp_proto;
		write_unlock_bh(global_lock);

		if (conn->ksnc_proto == NULL) {
			if (psa->sin_family == AF_INET6)
				conn->ksnc_proto = &ksocknal_protocol_v4x;
			else if (psa->sin_family == AF_INET)
				conn->ksnc_proto = &ksocknal_protocol_v3x;
#if SOCKNAL_VERSION_DEBUG
			if (*ksocknal_tunables.ksnd_protocol == 2)
				conn->ksnc_proto = &ksocknal_protocol_v2x;
			else if (*ksocknal_tunables.ksnd_protocol == 1)
				conn->ksnc_proto = &ksocknal_protocol_v1x;
#endif
		}
		if (!conn->ksnc_proto) {
			rc = -EPROTO;
			goto failed_1;
		}

		rc = ksocknal_send_hello(ni, conn, &peerid.nid, hello);
		if (rc != 0)
			goto failed_1;
	} else {
		peerid.nid = LNET_ANY_NID;
		peerid.pid = LNET_PID_ANY;

		/* Passive, get protocol from peer_ni */
		conn->ksnc_proto = NULL;
	}

	rc = ksocknal_recv_hello(ni, conn, hello, &peerid, &incarnation);
	if (rc < 0)
		goto failed_1;

	LASSERT(rc == 0 || active);
	LASSERT(conn->ksnc_proto != NULL);
	LASSERT(!LNET_NID_IS_ANY(&peerid.nid));

	cpt = lnet_nid2cpt(&peerid.nid, ni);

	if (active) {
		ksocknal_peer_addref(peer_ni);
		write_lock_bh(global_lock);
	} else {
		peer_ni = ksocknal_create_peer(ni, &peerid);
		if (IS_ERR(peer_ni)) {
			rc = PTR_ERR(peer_ni);
			goto failed_1;
		}

		write_lock_bh(global_lock);

		/* called with a ref on ni, so shutdown can't have started */
		LASSERT(atomic_read(&((struct ksock_net *)ni->ni_data)->ksnn_npeers) >= 0);

		peer2 = ksocknal_find_peer_locked(ni, &peerid);
		if (peer2 == NULL) {
			/* NB this puts an "empty" peer_ni in the peer_ni
			 * table (which takes my ref)
			 */
			hash_add(ksocknal_data.ksnd_peers,
				 &peer_ni->ksnp_list, nidhash(&peerid.nid));
		} else {
			ksocknal_peer_decref(peer_ni);
			peer_ni = peer2;
		}

		/* +1 ref for me */
		ksocknal_peer_addref(peer_ni);
		peer_ni->ksnp_accepting++;

		/* Am I already connecting to this guy?  Resolve in
		 * favour of higher NID...
		 */
		if (memcmp(&peerid.nid, &ni->ni_nid, sizeof(peerid.nid)) < 0 &&
		    ksocknal_connecting(peer_ni->ksnp_conn_cb,
					((struct sockaddr *) &conn->ksnc_peeraddr))) {
			rc = EALREADY;
			warn = "connection race resolution";
			goto failed_2;
		}
	}

	if (peer_ni->ksnp_closing ||
	    (active && conn_cb->ksnr_deleted)) {
		/* peer_ni/conn_cb got closed under me */
		rc = -ESTALE;
		warn = "peer_ni/conn_cb removed";
		goto failed_2;
	}

	if (peer_ni->ksnp_proto == NULL) {
		/* Never connected before.
		 * NB recv_hello may have returned EPROTO to signal my peer_ni
		 * wants a different protocol than the one I asked for.
		 */
		LASSERT(list_empty(&peer_ni->ksnp_conns));

		peer_ni->ksnp_proto = conn->ksnc_proto;
		peer_ni->ksnp_incarnation = incarnation;
	}

	if (peer_ni->ksnp_proto != conn->ksnc_proto ||
	    peer_ni->ksnp_incarnation != incarnation) {
		/* peer_ni rebooted or I've got the wrong protocol version */
		ksocknal_close_peer_conns_locked(peer_ni, NULL, 0);

		peer_ni->ksnp_proto = NULL;
		rc = ESTALE;
		warn = peer_ni->ksnp_incarnation != incarnation ?
			"peer_ni rebooted" :
			"wrong proto version";
		goto failed_2;
	}

	switch (rc) {
	default:
		LBUG();
	case 0:
		break;
	case EALREADY:
		warn = "lost conn race";
		goto failed_2;
	case EPROTO:
		warn = "retry with different protocol version";
		goto failed_2;
	}

	/* Refuse to duplicate an existing connection, unless this is a
	 * loopback connection
	 */
	if (!rpc_cmp_addr((struct sockaddr *)&conn->ksnc_peeraddr,
			  (struct sockaddr *)&conn->ksnc_myaddr)) {
		list_for_each_entry(conn2, &peer_ni->ksnp_conns, ksnc_list) {
			if (!rpc_cmp_addr(
				    (struct sockaddr *)&conn2->ksnc_peeraddr,
				    (struct sockaddr *)&conn->ksnc_peeraddr) ||
			    !rpc_cmp_addr(
				    (struct sockaddr *)&conn2->ksnc_myaddr,
				    (struct sockaddr *)&conn->ksnc_myaddr) ||
			    conn2->ksnc_type != conn->ksnc_type)
				continue;

			num_dup++;
			/* If max conns per type is not registered in conn_cb
			 * as ksnr_max_conns, use ni's conns_per_peer
			 */
			if ((peer_ni->ksnp_conn_cb &&
			    num_dup < peer_ni->ksnp_conn_cb->ksnr_max_conns) ||
			    (!peer_ni->ksnp_conn_cb &&
			    num_dup < ksocknal_get_conns_per_peer(peer_ni)))
				continue;

			/* Reply on a passive connection attempt so the peer_ni
			 * realises we're connected.
			 */
			LASSERT(rc == 0);
			if (!active)
				rc = EALREADY;

			warn = "duplicate";
			goto failed_2;
		}
	}
	/* If the connection created by this route didn't bind to the IP
	 * address the route connected to, the connection/route matching
	 * code below probably isn't going to work.
	 */
	if (active &&
	    !rpc_cmp_addr((struct sockaddr *)&conn_cb->ksnr_addr,
			  (struct sockaddr *)&conn->ksnc_peeraddr)) {
		CERROR("Route %s %pISc connected to %pISc\n",
		       libcfs_idstr(&peer_ni->ksnp_id),
		       &conn_cb->ksnr_addr,
		       &conn->ksnc_peeraddr);
	}

	/* Search for a conn_cb corresponding to the new connection and
	 * create an association.  This allows incoming connections created
	 * by conn_cbs in my peer_ni to match my own conn_cb entries so I don't
	 * continually create duplicate conn_cbs.
	 */
	conn_cb = peer_ni->ksnp_conn_cb;

	if (conn_cb && rpc_cmp_addr((struct sockaddr *)&conn->ksnc_peeraddr,
				    (struct sockaddr *)&conn_cb->ksnr_addr))
		ksocknal_associate_cb_conn_locked(conn_cb, conn);

	conn->ksnc_peer = peer_ni;                 /* conn takes my ref on peer_ni */
	peer_ni->ksnp_last_alive = ktime_get_seconds();
	peer_ni->ksnp_send_keepalive = 0;
	peer_ni->ksnp_error = 0;

	sched = ksocknal_choose_scheduler_locked(cpt);
	if (!sched) {
		CERROR("no schedulers available. node is unhealthy\n");
		goto failed_2;
	}
	/* The cpt might have changed if we ended up selecting a non cpt
	 * native scheduler. So use the scheduler's cpt instead.
	 */
	cpt = sched->kss_cpt;
	sched->kss_nconns++;
	conn->ksnc_scheduler = sched;

	conn->ksnc_tx_last_post = ktime_get_seconds();
	/* Set the deadline for the outgoing HELLO to drain */
	conn->ksnc_tx_bufnob = sock->sk->sk_wmem_queued;
	conn->ksnc_tx_deadline = ktime_get_seconds() +
				 ksocknal_timeout();
	smp_mb();   /* order with adding to peer_ni's conn list */

	list_add(&conn->ksnc_list, &peer_ni->ksnp_conns);
	ksocknal_conn_addref(conn);

	ksocknal_new_packet(conn, 0);

	conn->ksnc_zc_capable = ksocknal_lib_zc_capable(conn);

	/* Take packets blocking for this connection. */
	list_for_each_entry_safe(tx, txtmp, &peer_ni->ksnp_tx_queue, tx_list) {
		if (conn->ksnc_proto->pro_match_tx(conn, tx, tx->tx_nonblk) ==
		    SOCKNAL_MATCH_NO)
			continue;

		list_del(&tx->tx_list);
		ksocknal_queue_tx_locked(tx, conn);
	}

	write_unlock_bh(global_lock);
	/* We've now got a new connection.  Any errors from here on are just
	 * like "normal" comms errors and we close the connection normally.
	 * NB (a) we still have to send the reply HELLO for passive
	 *        connections,
	 *    (b) normal I/O on the conn is blocked until I setup and call the
	 *        socket callbacks.
	 */

	CDEBUG(D_NET, "New conn %s p %d.x %pISc -> %pIScp"
	       " incarnation:%lld sched[%d]\n",
	       libcfs_idstr(&peerid), conn->ksnc_proto->pro_version,
	       &conn->ksnc_myaddr, &conn->ksnc_peeraddr,
	       incarnation, cpt);

	if (!active) {
		hello->kshm_nips = 0;
		rc = ksocknal_send_hello(ni, conn, &peerid.nid, hello);
	}

	LIBCFS_FREE(hello, offsetof(struct ksock_hello_msg,
				    kshm_ips[LNET_INTERFACES_NUM]));

	/* setup the socket AFTER I've received hello (it disables
	 * SO_LINGER).  I might call back to the acceptor who may want
	 * to send a protocol version response and then close the
	 * socket; this ensures the socket only tears down after the
	 * response has been sent.
	 */
	if (rc == 0)
		rc = ksocknal_lib_setup_sock(sock, ni);

	write_lock_bh(global_lock);

	/* NB my callbacks block while I hold ksnd_global_lock */
	ksocknal_lib_set_callback(sock, conn);

	if (!active)
		peer_ni->ksnp_accepting--;

	write_unlock_bh(global_lock);

	if (rc != 0) {
		write_lock_bh(global_lock);
		if (!conn->ksnc_closing) {
			/* could be closed by another thread */
			ksocknal_close_conn_locked(conn, rc);
		}
		write_unlock_bh(global_lock);
	} else if (ksocknal_connsock_addref(conn) == 0) {
		/* Allow I/O to proceed. */
		ksocknal_read_callback(conn);
		ksocknal_write_callback(conn);
		ksocknal_connsock_decref(conn);
	}

	ksocknal_connsock_decref(conn);
	ksocknal_conn_decref(conn);
	return rc;

failed_2:

	if (!peer_ni->ksnp_closing &&
	    list_empty(&peer_ni->ksnp_conns) &&
	    peer_ni->ksnp_conn_cb == NULL) {
		list_splice_init(&peer_ni->ksnp_tx_queue, &zombies);
		ksocknal_unlink_peer_locked(peer_ni);
	}

	write_unlock_bh(global_lock);

	if (warn != NULL) {
		if (rc < 0)
			CERROR("Not creating conn %s type %d: %s\n",
			       libcfs_idstr(&peerid), conn->ksnc_type, warn);
		else
			CDEBUG(D_NET, "Not creating conn %s type %d: %s\n",
			       libcfs_idstr(&peerid), conn->ksnc_type, warn);
	}

	if (!active) {
		if (rc > 0) {
			/* Request retry by replying with CONN_NONE
			 * ksnc_proto has been set already
			 */
			conn->ksnc_type = SOCKLND_CONN_NONE;
			hello->kshm_nips = 0;
			ksocknal_send_hello(ni, conn, &peerid.nid, hello);
		}

		write_lock_bh(global_lock);
		peer_ni->ksnp_accepting--;
		write_unlock_bh(global_lock);
	}

	/* If we get here without an error code, just use -EALREADY.
	 * Depending on how we got here, the error may be positive
	 * or negative. Normalize the value for ksocknal_txlist_done().
	 */
	rc2 = (rc == 0 ? -EALREADY : (rc > 0 ? -rc : rc));
	ksocknal_txlist_done(ni, &zombies, rc2);
	ksocknal_peer_decref(peer_ni);

failed_1:
	LIBCFS_FREE(hello, offsetof(struct ksock_hello_msg,
				    kshm_ips[LNET_INTERFACES_NUM]));

	LIBCFS_FREE(conn, sizeof(*conn));

failed_0:
	sock_release(sock);

	return rc;
}

void
ksocknal_close_conn_locked(struct ksock_conn *conn, int error)
{
	/* This just does the immmediate housekeeping, and queues the
	 * connection for the reaper to terminate.
	 * Caller holds ksnd_global_lock exclusively in irq context
	 */
	struct ksock_peer_ni *peer_ni = conn->ksnc_peer;
	struct ksock_conn_cb *conn_cb;
	struct ksock_conn *conn2;
	int conn_count;
	int duplicate_count = 0;

	LASSERT(peer_ni->ksnp_error == 0);
	LASSERT(!conn->ksnc_closing);
	conn->ksnc_closing = 1;

	/* ksnd_deathrow_conns takes over peer_ni's ref */
	list_del(&conn->ksnc_list);

	conn_cb = conn->ksnc_conn_cb;
	if (conn_cb != NULL) {
		/* dissociate conn from cb... */
		LASSERT(!conn_cb->ksnr_deleted);

		conn_count = ksocknal_get_conn_count_by_type(conn_cb,
							     conn->ksnc_type);
		/* connected bit is set only if all connections
		 * of the given type got created
		 */
		if (conn_count == conn_cb->ksnr_max_conns)
			LASSERT((conn_cb->ksnr_connected &
				BIT(conn->ksnc_type)) != 0);

		if (conn_count == 1) {
			list_for_each_entry(conn2, &peer_ni->ksnp_conns,
					    ksnc_list) {
				if (conn2->ksnc_conn_cb == conn_cb &&
				    conn2->ksnc_type == conn->ksnc_type)
					duplicate_count += 1;
			}
			if (duplicate_count > 0)
				CERROR("Found %d duplicate conns type %d\n",
				       duplicate_count,
				       conn->ksnc_type);
		}
		ksocknal_decr_conn_count(conn_cb, conn->ksnc_type);

		conn->ksnc_conn_cb = NULL;

		/* drop conn's ref on conn_cb */
		ksocknal_conn_cb_decref(conn_cb);
	}

	if (list_empty(&peer_ni->ksnp_conns)) {
		/* No more connections to this peer_ni */

		if (!list_empty(&peer_ni->ksnp_tx_queue)) {
			struct ksock_tx *tx;

			LASSERT(conn->ksnc_proto == &ksocknal_protocol_v3x);

			/* throw them to the last connection...,
			 * these TXs will be send to /dev/null by scheduler
			 */
			list_for_each_entry(tx, &peer_ni->ksnp_tx_queue,
					    tx_list)
				ksocknal_tx_prep(conn, tx);

			spin_lock_bh(&conn->ksnc_scheduler->kss_lock);
			list_splice_init(&peer_ni->ksnp_tx_queue,
					 &conn->ksnc_tx_queue);
			spin_unlock_bh(&conn->ksnc_scheduler->kss_lock);
		}

		/* renegotiate protocol version */
		peer_ni->ksnp_proto = NULL;
		/* stash last conn close reason */
		peer_ni->ksnp_error = error;

		if (peer_ni->ksnp_conn_cb == NULL) {
			/* I've just closed last conn belonging to a
			 * peer_ni with no connections to it
			 */
			ksocknal_unlink_peer_locked(peer_ni);
		}
	}

	spin_lock_bh(&ksocknal_data.ksnd_reaper_lock);

	list_add_tail(&conn->ksnc_list, &ksocknal_data.ksnd_deathrow_conns);
	wake_up(&ksocknal_data.ksnd_reaper_waitq);

	spin_unlock_bh(&ksocknal_data.ksnd_reaper_lock);
}

void
ksocknal_peer_failed(struct ksock_peer_ni *peer_ni)
{
	bool notify = false;
	time64_t last_alive = 0;

	/* There has been a connection failure or comms error; but I'll only
	 * tell LNET I think the peer_ni is dead if it's to another kernel and
	 * there are no connections or connection attempts in existence.
	 */
	read_lock(&ksocknal_data.ksnd_global_lock);

	if ((peer_ni->ksnp_id.pid & LNET_PID_USERFLAG) == 0 &&
	     list_empty(&peer_ni->ksnp_conns) &&
	     peer_ni->ksnp_accepting == 0 &&
	     !ksocknal_find_connecting_conn_cb_locked(peer_ni)) {
		notify = true;
		last_alive = peer_ni->ksnp_last_alive;
	}

	read_unlock(&ksocknal_data.ksnd_global_lock);

	if (notify)
		lnet_notify(peer_ni->ksnp_ni,
			    &peer_ni->ksnp_id.nid,
			    false, false, last_alive);
}

void
ksocknal_finalize_zcreq(struct ksock_conn *conn)
{
	struct ksock_peer_ni *peer_ni = conn->ksnc_peer;
	struct ksock_tx *tx;
	struct ksock_tx *tmp;
	LIST_HEAD(zlist);

	/* NB safe to finalize TXs because closing of socket will
	 * abort all buffered data
	 */
	LASSERT(conn->ksnc_sock == NULL);

	spin_lock(&peer_ni->ksnp_lock);

	list_for_each_entry_safe(tx, tmp, &peer_ni->ksnp_zc_req_list,
				 tx_zc_list) {
		if (tx->tx_conn != conn)
			continue;

		LASSERT(tx->tx_msg.ksm_zc_cookies[0] != 0);

		tx->tx_msg.ksm_zc_cookies[0] = 0;
		tx->tx_zc_aborted = 1;	/* mark it as not-acked */
		list_move(&tx->tx_zc_list, &zlist);
	}

	spin_unlock(&peer_ni->ksnp_lock);

	while ((tx = list_first_entry_or_null(&zlist, struct ksock_tx,
					      tx_zc_list)) != NULL) {
		list_del(&tx->tx_zc_list);
		ksocknal_tx_decref(tx);
	}
}

void
ksocknal_terminate_conn(struct ksock_conn *conn)
{
	/* This gets called by the reaper (guaranteed thread context) to
	 * disengage the socket from its callbacks and close it.
	 * ksnc_refcount will eventually hit zero, and then the reaper will
	 * destroy it.
	 */
	struct ksock_peer_ni *peer_ni = conn->ksnc_peer;
	struct ksock_sched *sched = conn->ksnc_scheduler;
	bool failed = false;

	LASSERT(conn->ksnc_closing);

	/* wake up the scheduler to "send" all remaining packets to /dev/null */
	spin_lock_bh(&sched->kss_lock);

	/* a closing conn is always ready to tx */
	conn->ksnc_tx_ready = 1;

	if (!conn->ksnc_tx_scheduled &&
	    !list_empty(&conn->ksnc_tx_queue)) {
		list_add_tail(&conn->ksnc_tx_list,
			      &sched->kss_tx_conns);
		conn->ksnc_tx_scheduled = 1;
		/* extra ref for scheduler */
		ksocknal_conn_addref(conn);

		wake_up(&sched->kss_waitq);
	}

	spin_unlock_bh(&sched->kss_lock);

	/* serialise with callbacks */
	write_lock_bh(&ksocknal_data.ksnd_global_lock);

	ksocknal_lib_reset_callback(conn->ksnc_sock, conn);

	/* OK, so this conn may not be completely disengaged from its
	 * scheduler yet, but it _has_ committed to terminate...
	 */
	conn->ksnc_scheduler->kss_nconns--;

	if (peer_ni->ksnp_error != 0) {
		/* peer_ni's last conn closed in error */
		LASSERT(list_empty(&peer_ni->ksnp_conns));
		failed = true;
		peer_ni->ksnp_error = 0;     /* avoid multiple notifications */
	}

	write_unlock_bh(&ksocknal_data.ksnd_global_lock);

	if (failed)
		ksocknal_peer_failed(peer_ni);

	/* The socket is closed on the final put; either here, or in
	 * ksocknal_{send,recv}msg().  Since we set up the linger2 option
	 * when the connection was established, this will close the socket
	 * immediately, aborting anything buffered in it. Any hung
	 * zero-copy transmits will therefore complete in finite time.
	 */
	ksocknal_connsock_decref(conn);
}

void
ksocknal_queue_zombie_conn(struct ksock_conn *conn)
{
	/* Queue the conn for the reaper to destroy */
	LASSERT(refcount_read(&conn->ksnc_conn_refcount) == 0);
	spin_lock_bh(&ksocknal_data.ksnd_reaper_lock);

	list_add_tail(&conn->ksnc_list, &ksocknal_data.ksnd_zombie_conns);
	wake_up(&ksocknal_data.ksnd_reaper_waitq);

	spin_unlock_bh(&ksocknal_data.ksnd_reaper_lock);
}

void
ksocknal_destroy_conn(struct ksock_conn *conn)
{
	time64_t last_rcv;

	/* Final coup-de-grace of the reaper */
	CDEBUG(D_NET, "connection %p\n", conn);

	LASSERT(refcount_read(&conn->ksnc_conn_refcount) == 0);
	LASSERT(refcount_read(&conn->ksnc_sock_refcount) == 0);
	LASSERT(conn->ksnc_sock == NULL);
	LASSERT(conn->ksnc_conn_cb == NULL);
	LASSERT(!conn->ksnc_tx_scheduled);
	LASSERT(!conn->ksnc_rx_scheduled);
	LASSERT(list_empty(&conn->ksnc_tx_queue));

	/* complete current receive if any */
	switch (conn->ksnc_rx_state) {
	case SOCKNAL_RX_LNET_PAYLOAD:
		last_rcv = conn->ksnc_rx_deadline -
			   ksocknal_timeout();
		CERROR("Completing partial receive from %s[%d], ip %pIScp, with error, wanted: %d, left: %d, last alive is %lld secs ago\n",
		       libcfs_idstr(&conn->ksnc_peer->ksnp_id),
		       conn->ksnc_type,
		       &conn->ksnc_peeraddr,
		       conn->ksnc_rx_nob_wanted, conn->ksnc_rx_nob_left,
		       ktime_get_seconds() - last_rcv);
		if (conn->ksnc_lnet_msg)
			conn->ksnc_lnet_msg->msg_health_status =
				LNET_MSG_STATUS_REMOTE_ERROR;
		lnet_finalize(conn->ksnc_lnet_msg, -EIO);
		break;
	case SOCKNAL_RX_LNET_HEADER:
		if (conn->ksnc_rx_started)
			CERROR("Incomplete receive of lnet header from %s, ip %pIScp, with error, protocol: %d.x.\n",
			       libcfs_idstr(&conn->ksnc_peer->ksnp_id),
			       &conn->ksnc_peeraddr,
			       conn->ksnc_proto->pro_version);
		break;
	case SOCKNAL_RX_KSM_HEADER:
		if (conn->ksnc_rx_started)
			CERROR("Incomplete receive of ksock message from %s, ip %pIScp, with error, protocol: %d.x.\n",
			       libcfs_idstr(&conn->ksnc_peer->ksnp_id),
			       &conn->ksnc_peeraddr,
			       conn->ksnc_proto->pro_version);
		break;
	case SOCKNAL_RX_SLOP:
		if (conn->ksnc_rx_started)
			CERROR("Incomplete receive of slops from %s, ip %pIScp, with error\n",
			       libcfs_idstr(&conn->ksnc_peer->ksnp_id),
			       &conn->ksnc_peeraddr);
		break;
	default:
		LBUG();
		break;
	}

	ksocknal_peer_decref(conn->ksnc_peer);

	LIBCFS_FREE(conn, sizeof(*conn));
}

int
ksocknal_close_peer_conns_locked(struct ksock_peer_ni *peer_ni,
				 struct sockaddr *addr, int why)
{
	struct ksock_conn *conn;
	struct ksock_conn *cnxt;
	int count = 0;

	list_for_each_entry_safe(conn, cnxt, &peer_ni->ksnp_conns, ksnc_list) {
		if (!addr ||
		    rpc_cmp_addr(addr,
				 (struct sockaddr *)&conn->ksnc_peeraddr)) {
			count++;
			ksocknal_close_conn_locked(conn, why);
		}
	}

	return count;
}

int
ksocknal_close_conn_and_siblings(struct ksock_conn *conn, int why)
{
	struct ksock_peer_ni *peer_ni = conn->ksnc_peer;
	int count;

	write_lock_bh(&ksocknal_data.ksnd_global_lock);

	count = ksocknal_close_peer_conns_locked(
		peer_ni, (struct sockaddr *)&conn->ksnc_peeraddr, why);

	write_unlock_bh(&ksocknal_data.ksnd_global_lock);

	return count;
}

int
ksocknal_close_matching_conns(struct lnet_processid *id, __u32 ipaddr)
{
	struct ksock_peer_ni *peer_ni;
	struct hlist_node *pnxt;
	int lo;
	int hi;
	int i;
	int count = 0;
	struct sockaddr_in sa = {.sin_family = AF_INET};

	write_lock_bh(&ksocknal_data.ksnd_global_lock);

	if (!LNET_NID_IS_ANY(&id->nid)) {
		lo = hash_min(nidhash(&id->nid),
			      HASH_BITS(ksocknal_data.ksnd_peers));
		hi = lo;
	} else {
		lo = 0;
		hi = HASH_SIZE(ksocknal_data.ksnd_peers) - 1;
	}

	sa.sin_addr.s_addr = htonl(ipaddr);
	for (i = lo; i <= hi; i++) {
		hlist_for_each_entry_safe(peer_ni, pnxt,
					  &ksocknal_data.ksnd_peers[i],
					  ksnp_list) {

			if (!((LNET_NID_IS_ANY(&id->nid) ||
			       nid_same(&id->nid, &peer_ni->ksnp_id.nid)) &&
			      (id->pid == LNET_PID_ANY ||
			       id->pid == peer_ni->ksnp_id.pid)))
				continue;

			count += ksocknal_close_peer_conns_locked(
				peer_ni,
				ipaddr ? (struct sockaddr *)&sa : NULL, 0);
		}
	}

	write_unlock_bh(&ksocknal_data.ksnd_global_lock);

	/* wildcards always succeed */
	if (LNET_NID_IS_ANY(&id->nid) || id->pid == LNET_PID_ANY ||
	    ipaddr == 0)
		return 0;

	return (count == 0 ? -ENOENT : 0);
}

static void
ksocknal_notify_gw_down(struct lnet_nid *gw_nid)
{
	/* The router is telling me she's been notified of a change in
	 * gateway state....
	 */
	struct lnet_processid id = {
		.pid	= LNET_PID_ANY,
		.nid	= *gw_nid,
	};

	CDEBUG(D_NET, "gw %s down\n", libcfs_nidstr(gw_nid));

	/* If the gateway crashed, close all open connections... */
	ksocknal_close_matching_conns(&id, 0);
	return;

	/* We can only establish new connections
	 * if we have autroutes, and these connect on demand.
	 */
}

static void
ksocknal_push_peer(struct ksock_peer_ni *peer_ni)
{
	int index;
	int i;
	struct ksock_conn *conn;

	for (index = 0; ; index++) {
		read_lock(&ksocknal_data.ksnd_global_lock);

		i = 0;
		conn = NULL;

		list_for_each_entry(conn, &peer_ni->ksnp_conns, ksnc_list) {
			if (i++ == index) {
				ksocknal_conn_addref(conn);
				break;
			}
		}

		read_unlock(&ksocknal_data.ksnd_global_lock);

		if (i <= index)
			break;

		ksocknal_lib_push_conn(conn);
		ksocknal_conn_decref(conn);
	}
}

static int
ksocknal_push(struct lnet_ni *ni, struct lnet_processid *id)
{
	int lo;
	int hi;
	int bkt;
	int rc = -ENOENT;

	if (!LNET_NID_IS_ANY(&id->nid)) {
		lo = hash_min(nidhash(&id->nid),
			      HASH_BITS(ksocknal_data.ksnd_peers));
		hi = lo;
	} else {
		lo = 0;
		hi = HASH_SIZE(ksocknal_data.ksnd_peers) - 1;
	}

	for (bkt = lo; bkt <= hi; bkt++) {
		int peer_off; /* searching offset in peer_ni hash table */

		for (peer_off = 0; ; peer_off++) {
			struct ksock_peer_ni *peer_ni;
			int	      i = 0;

			read_lock(&ksocknal_data.ksnd_global_lock);
			hlist_for_each_entry(peer_ni,
					     &ksocknal_data.ksnd_peers[bkt],
					     ksnp_list) {
				if (!((LNET_NID_IS_ANY(&id->nid) ||
				       nid_same(&id->nid,
						 &peer_ni->ksnp_id.nid)) &&
				      (id->pid == LNET_PID_ANY ||
				       id->pid == peer_ni->ksnp_id.pid)))
					continue;

				if (i++ == peer_off) {
					ksocknal_peer_addref(peer_ni);
					break;
				}
			}
			read_unlock(&ksocknal_data.ksnd_global_lock);

			if (i <= peer_off) /* no match */
				break;

			rc = 0;
			ksocknal_push_peer(peer_ni);
			ksocknal_peer_decref(peer_ni);
		}
	}
	return rc;
}

int
ksocknal_ctl(struct lnet_ni *ni, unsigned int cmd, void *arg)
{
	struct lnet_processid id = {};
	struct libcfs_ioctl_data *data = arg;
	int rc;

	switch (cmd) {
	case IOC_LIBCFS_GET_INTERFACE: {
		struct ksock_net *net = ni->ni_data;
		struct ksock_interface *iface;
		struct sockaddr_in *sa;

		read_lock(&ksocknal_data.ksnd_global_lock);

		if (data->ioc_count >= 1) {
			rc = -ENOENT;
		} else {
			rc = 0;
			iface = &net->ksnn_interface;

			sa = (void *)&iface->ksni_addr;
			if (sa->sin_family == AF_INET) {
				data->ioc_u32[0] = ntohl(sa->sin_addr.s_addr);
				data->ioc_u32[1] = iface->ksni_netmask;
			} else {
				data->ioc_u32[0] = 0xFFFFFFFF;
				data->ioc_u32[1] = 0;
			}
			data->ioc_u32[2] = iface->ksni_npeers;
			data->ioc_u32[3] = iface->ksni_nroutes;
		}

		read_unlock(&ksocknal_data.ksnd_global_lock);
		return rc;
	}

	case IOC_LIBCFS_GET_PEER: {
		__u32            myip = 0;
		__u32            ip = 0;
		int              port = 0;
		int              conn_count = 0;
		int              share_count = 0;

		rc = ksocknal_get_peer_info(ni, data->ioc_count,
					    &id, &myip, &ip, &port,
					    &conn_count,  &share_count);
		if (rc != 0)
			return rc;

		if (!nid_is_nid4(&id.nid))
			return -EINVAL;
		data->ioc_nid    = lnet_nid_to_nid4(&id.nid);
		data->ioc_count  = share_count;
		data->ioc_u32[0] = ip;
		data->ioc_u32[1] = port;
		data->ioc_u32[2] = myip;
		data->ioc_u32[3] = conn_count;
		data->ioc_u32[4] = id.pid;
		return 0;
	}

	case IOC_LIBCFS_ADD_PEER: {
		struct sockaddr_in sa = {.sin_family = AF_INET};

		id.pid = LNET_PID_LUSTRE;
		lnet_nid4_to_nid(data->ioc_nid, &id.nid);
		sa.sin_addr.s_addr = htonl(data->ioc_u32[0]);
		sa.sin_port = htons(data->ioc_u32[1]);
		return ksocknal_add_peer(ni, &id, (struct sockaddr *)&sa);
	}
	case IOC_LIBCFS_DEL_PEER:
		lnet_nid4_to_nid(data->ioc_nid, &id.nid);
		id.pid = LNET_PID_ANY;
		return ksocknal_del_peer(ni, &id);

	case IOC_LIBCFS_GET_CONN: {
		int           txmem;
		int           rxmem;
		int           nagle;
		struct ksock_conn *conn = ksocknal_get_conn_by_idx(ni, data->ioc_count);
		struct sockaddr_in *psa = (void *)&conn->ksnc_peeraddr;
		struct sockaddr_in *mysa = (void *)&conn->ksnc_myaddr;

		if (conn == NULL)
			return -ENOENT;

		ksocknal_lib_get_conn_tunables(conn, &txmem, &rxmem, &nagle);

		data->ioc_count = txmem;
		data->ioc_nid = lnet_nid_to_nid4(&conn->ksnc_peer->ksnp_id.nid);
		data->ioc_flags = nagle;
		if (psa->sin_family == AF_INET)
			data->ioc_u32[0] = ntohl(psa->sin_addr.s_addr);
		else
			data->ioc_u32[0] = 0xFFFFFFFF;
		data->ioc_u32[1] = rpc_get_port((struct sockaddr *)
						&conn->ksnc_peeraddr);
		if (mysa->sin_family == AF_INET)
			data->ioc_u32[2] = ntohl(mysa->sin_addr.s_addr);
		else
			data->ioc_u32[2] = 0xFFFFFFFF;
		data->ioc_u32[3] = conn->ksnc_type;
		data->ioc_u32[4] = conn->ksnc_scheduler->kss_cpt;
		data->ioc_u32[5] = rxmem;
		data->ioc_u32[6] = conn->ksnc_peer->ksnp_id.pid;
		ksocknal_conn_decref(conn);
		return 0;
	}

	case IOC_LIBCFS_CLOSE_CONNECTION:
		lnet_nid4_to_nid(data->ioc_nid, &id.nid);
		id.pid = LNET_PID_ANY;
		return ksocknal_close_matching_conns(&id,
						     data->ioc_u32[0]);

	case IOC_LIBCFS_REGISTER_MYNID:
		/* Ignore if this is a noop */
		if (nid_is_nid4(&ni->ni_nid) &&
		    data->ioc_nid == lnet_nid_to_nid4(&ni->ni_nid))
			return 0;

		CERROR("obsolete IOC_LIBCFS_REGISTER_MYNID: %s(%s)\n",
		       libcfs_nid2str(data->ioc_nid),
		       libcfs_nidstr(&ni->ni_nid));
		return -EINVAL;

	case IOC_LIBCFS_PUSH_CONNECTION:
		lnet_nid4_to_nid(data->ioc_nid, &id.nid);
		id.pid = LNET_PID_ANY;
		return ksocknal_push(ni, &id);

	default:
		return -EINVAL;
	}
	/* not reached */
}

static void
ksocknal_free_buffers(void)
{
	LASSERT(atomic_read(&ksocknal_data.ksnd_nactive_txs) == 0);

	if (ksocknal_data.ksnd_schedulers != NULL)
		cfs_percpt_free(ksocknal_data.ksnd_schedulers);

	spin_lock(&ksocknal_data.ksnd_tx_lock);

	if (!list_empty(&ksocknal_data.ksnd_idle_noop_txs)) {
		LIST_HEAD(zlist);
		struct ksock_tx	*tx;

		list_splice_init(&ksocknal_data.ksnd_idle_noop_txs, &zlist);
		spin_unlock(&ksocknal_data.ksnd_tx_lock);

		while ((tx = list_first_entry_or_null(&zlist, struct ksock_tx,
						      tx_list)) != NULL) {
			list_del(&tx->tx_list);
			LIBCFS_FREE(tx, tx->tx_desc_size);
		}
	} else {
		spin_unlock(&ksocknal_data.ksnd_tx_lock);
	}
}

static int
ksocknal_handle_link_state_change(struct net_device *dev,
				  unsigned char operstate)
{
	struct lnet_ni *ni = NULL;
	struct ksock_net *net;
	struct ksock_net *cnxt;
	int ifindex;
	unsigned char link_down;
	bool found_ip = false;
	struct ksock_interface *ksi = NULL;
	struct sockaddr *sa = NULL;
	u32 ni_state_before;
	bool update_ping_buf = false;
	int state;

	link_down = !((operstate == IF_OPER_UP) || (operstate == IF_OPER_UNKNOWN));
	ifindex = dev->ifindex;

	if (!ksocknal_data.ksnd_nnets)
		goto out;

	list_for_each_entry_safe(net, cnxt, &ksocknal_data.ksnd_nets,
				 ksnn_list) {
		ksi = &net->ksnn_interface;
		found_ip = false;

		if (strcmp(ksi->ksni_name, dev->name))
			continue;

		if (ksi->ksni_index == -1) {
			if (dev->reg_state != NETREG_REGISTERED)
				continue;
			/* A registration just happened: save the new index for
			 * the device
			 */
			ksi->ksni_index = ifindex;
			goto out;
		}

		if (ksi->ksni_index != ifindex)
			continue;

		if (dev->reg_state == NETREG_UNREGISTERING) {
			/* Device is being unregistered, we need to clear the
			 * index, it can change when device will be back
			 */
			ksi->ksni_index = -1;
			goto out;
		}

		ni = net->ksnn_ni;

		sa = (void *)&ksi->ksni_addr;
		switch (sa->sa_family) {
		case AF_INET: {
			struct in_device *in_dev = __in_dev_get_rtnl(dev);
			DECLARE_CONST_IN_IFADDR(ifa);

			if (in_dev) {
				struct sockaddr_in *sa4;

				sa4 = (struct sockaddr_in *)sa;
				in_dev_for_each_ifa_rtnl(ifa, in_dev) {
					if (sa4->sin_addr.s_addr ==
					    ifa->ifa_local)
						found_ip = true;
				}
				endfor_ifa(in_dev);
			} else {
				sa = NULL;
			}
			break;
		}
#if IS_ENABLED(CONFIG_IPV6)
		case AF_INET6:{
			struct inet6_dev *in6_dev = __in6_dev_get(dev);

			if (in6_dev) {
				const struct inet6_ifaddr *ifa6;
				struct sockaddr_in6 *sa6;

				sa6 = (struct sockaddr_in6 *)sa;
				list_for_each_entry_rcu(ifa6,
							&in6_dev->addr_list,
							if_list) {
					if (!ipv6_addr_cmp(&ifa6->addr,
							   &sa6->sin6_addr)) {
						found_ip = true;
					}
				}
			} else {
				sa = NULL;
			}
			break;
		}
#endif
		default:
			sa = NULL;
			break;
		}

		if (!sa || !found_ip) {
			if (!sa) {
				CDEBUG(D_NET,
				       "Interface %s has no IP status.\n",
				       dev->name);
			} else {
				CDEBUG(D_NET,
				       "Interface %s has no matching IP\n",
				       dev->name);
			}
			ni_state_before = lnet_set_link_fatal_state(ni, 1);
			goto ni_done;
		}

		if (link_down) {
			ni_state_before = lnet_set_link_fatal_state(ni, 1);
		} else {
			state = (lnet_get_link_status(dev) == 0);
			ni_state_before = lnet_set_link_fatal_state(ni,
								    state);
		}
ni_done:
		if (!update_ping_buf &&
		    (ni->ni_state == LNET_NI_STATE_ACTIVE) &&
		    (atomic_read(&ni->ni_fatal_error_on) != ni_state_before))
			update_ping_buf = true;
	}

	if (update_ping_buf)
		lnet_mark_ping_buffer_for_update();
out:
	return 0;
}


static int
ksocknal_handle_inetaddr_change(struct net_device *event_netdev, unsigned long event)
{
	struct lnet_ni *ni = NULL;
	struct ksock_net *net;
	struct ksock_net *cnxt;
	int ifindex;
	struct ksock_interface *ksi = NULL;
	struct sockaddr *sa;
	u32 ni_state_before;
	bool update_ping_buf = false;
	bool link_down;

	if (!ksocknal_data.ksnd_nnets)
		goto out;

	ifindex = event_netdev->ifindex;

	list_for_each_entry_safe(net, cnxt, &ksocknal_data.ksnd_nets,
				 ksnn_list) {
		ksi = &net->ksnn_interface;
		sa = (void *)&ksi->ksni_addr;

		if (ksi->ksni_index != ifindex ||
		    strcmp(ksi->ksni_name, event_netdev->name))
			continue;

		ni = net->ksnn_ni;
		if (nid_is_nid4(&ni->ni_nid) ^ (sa->sa_family == AF_INET))
			continue;

		link_down = (event == NETDEV_DOWN);
		ni_state_before = lnet_set_link_fatal_state(ni,
							    link_down);

		if (!update_ping_buf &&
		    (ni->ni_state == LNET_NI_STATE_ACTIVE) &&
		    ((event == NETDEV_DOWN) != ni_state_before))
			update_ping_buf = true;
	}

	if (update_ping_buf)
		lnet_mark_ping_buffer_for_update();
out:
	return 0;
}

/************************************
 * Net device notifier event handler
 ************************************/
static int ksocknal_device_event(struct notifier_block *unused,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	unsigned char operstate;

	operstate = dev->operstate;

	CDEBUG(D_NET, "devevent: status=%s, iface=%s ifindex %d state %u\n",
	       netdev_cmd_to_name(event), dev->name, dev->ifindex, operstate);

	switch (event) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
	case NETDEV_REGISTER:
	case NETDEV_UNREGISTER:
		ksocknal_handle_link_state_change(dev, operstate);
		break;
	}

	return NOTIFY_OK;
}

/************************************
 * Inetaddr notifier event handler
 ************************************/
static int ksocknal_inetaddr_event(struct notifier_block *unused,
				   unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = ptr;

	CDEBUG(D_NET, "addrevent: status %s device %s, ip addr %pI4, netmask %pI4.\n",
		netdev_cmd_to_name(event), ifa->ifa_dev->dev->name,
		&ifa->ifa_address, &ifa->ifa_mask);

	switch (event) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
		ksocknal_handle_inetaddr_change(ifa->ifa_dev->dev, event);
		break;

	}
	return NOTIFY_OK;
}

static struct notifier_block ksocknal_dev_notifier_block = {
	.notifier_call = ksocknal_device_event,
};

static struct notifier_block ksocknal_inetaddr_notifier_block = {
	.notifier_call = ksocknal_inetaddr_event,
};

#if IS_ENABLED(CONFIG_IPV6)
static int ksocknal_inet6addr_event(struct notifier_block *this,
				    unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa6 = ptr;

	CDEBUG(D_NET, "addr6event: status %s, device %s, ip addr %pISc\n",
		netdev_cmd_to_name(event), ifa6->idev->dev->name, &ifa6->addr);

	switch (event) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
		ksocknal_handle_inetaddr_change(ifa6->idev->dev, event);
		break;

	}
	return NOTIFY_OK;
}

static struct notifier_block ksocknal_inet6addr_notifier_block = {
	.notifier_call = ksocknal_inet6addr_event,
};
#endif

static void
ksocknal_base_shutdown(void)
{
	struct ksock_sched *sched;
	struct ksock_peer_ni *peer_ni;
	int i;

	CDEBUG(D_MALLOC, "before NAL cleanup: kmem %lld\n",
	       libcfs_kmem_read());
	LASSERT(ksocknal_data.ksnd_nnets == 0);

	if (ksocknal_data.ksnd_init == SOCKNAL_INIT_ALL) {
		unregister_netdevice_notifier(&ksocknal_dev_notifier_block);
		unregister_inetaddr_notifier(&ksocknal_inetaddr_notifier_block);
#if IS_ENABLED(CONFIG_IPV6)
		unregister_inet6addr_notifier(&ksocknal_inet6addr_notifier_block);
#endif
	}

	switch (ksocknal_data.ksnd_init) {
	default:
		LASSERT(0);
		fallthrough;

	case SOCKNAL_INIT_ALL:
	case SOCKNAL_INIT_DATA:
		hash_for_each(ksocknal_data.ksnd_peers, i, peer_ni, ksnp_list)
			LASSERT(0);

		LASSERT(list_empty(&ksocknal_data.ksnd_nets));
		LASSERT(list_empty(&ksocknal_data.ksnd_enomem_conns));
		LASSERT(list_empty(&ksocknal_data.ksnd_zombie_conns));
		LASSERT(list_empty(&ksocknal_data.ksnd_connd_connreqs));
		LASSERT(list_empty(&ksocknal_data.ksnd_connd_routes));

		if (ksocknal_data.ksnd_schedulers != NULL) {
			cfs_percpt_for_each(sched, i,
					    ksocknal_data.ksnd_schedulers) {

				LASSERT(list_empty(&sched->kss_tx_conns));
				LASSERT(list_empty(&sched->kss_rx_conns));
				LASSERT(list_empty(&sched->kss_zombie_noop_txs));
				LASSERT(sched->kss_nconns == 0);
			}
		}

		/* flag threads to terminate; wake and wait for them to die */
		ksocknal_data.ksnd_shuttingdown = 1;
		wake_up_all(&ksocknal_data.ksnd_connd_waitq);
		wake_up(&ksocknal_data.ksnd_reaper_waitq);

		if (ksocknal_data.ksnd_schedulers != NULL) {
			cfs_percpt_for_each(sched, i,
					    ksocknal_data.ksnd_schedulers)
					wake_up_all(&sched->kss_waitq);
		}

		wait_var_event_warning(&ksocknal_data.ksnd_nthreads,
				       atomic_read(&ksocknal_data.ksnd_nthreads) == 0,
				       "waiting for %d threads to terminate\n",
				       atomic_read(&ksocknal_data.ksnd_nthreads));

		ksocknal_free_buffers();

		ksocknal_data.ksnd_init = SOCKNAL_INIT_NOTHING;
		break;
	}

	CDEBUG(D_MALLOC, "after NAL cleanup: kmem %lld\n",
	       libcfs_kmem_read());

	module_put(THIS_MODULE);
}

static int
ksocknal_base_startup(void)
{
	struct ksock_sched *sched;
	int rc;
	int i;

	LASSERT(ksocknal_data.ksnd_init == SOCKNAL_INIT_NOTHING);
	LASSERT(ksocknal_data.ksnd_nnets == 0);

	memset(&ksocknal_data, 0, sizeof(ksocknal_data)); /* zero pointers */

	hash_init(ksocknal_data.ksnd_peers);

	rwlock_init(&ksocknal_data.ksnd_global_lock);
	INIT_LIST_HEAD(&ksocknal_data.ksnd_nets);

	spin_lock_init(&ksocknal_data.ksnd_reaper_lock);
	INIT_LIST_HEAD(&ksocknal_data.ksnd_enomem_conns);
	INIT_LIST_HEAD(&ksocknal_data.ksnd_zombie_conns);
	INIT_LIST_HEAD(&ksocknal_data.ksnd_deathrow_conns);
	init_waitqueue_head(&ksocknal_data.ksnd_reaper_waitq);

	spin_lock_init(&ksocknal_data.ksnd_connd_lock);
	INIT_LIST_HEAD(&ksocknal_data.ksnd_connd_connreqs);
	INIT_LIST_HEAD(&ksocknal_data.ksnd_connd_routes);
	init_waitqueue_head(&ksocknal_data.ksnd_connd_waitq);

	spin_lock_init(&ksocknal_data.ksnd_tx_lock);
	INIT_LIST_HEAD(&ksocknal_data.ksnd_idle_noop_txs);

	/* NB memset above zeros whole of ksocknal_data */

	/* flag lists/ptrs/locks initialised */
	ksocknal_data.ksnd_init = SOCKNAL_INIT_DATA;
	if (!try_module_get(THIS_MODULE))
		goto failed;

	/* Create a scheduler block per available CPT */
	ksocknal_data.ksnd_schedulers = cfs_percpt_alloc(lnet_cpt_table(),
							 sizeof(*sched));
	if (ksocknal_data.ksnd_schedulers == NULL)
		goto failed;

	cfs_percpt_for_each(sched, i, ksocknal_data.ksnd_schedulers) {
		int nthrs;

		/* make sure not to allocate more threads than there are
		 * cores/CPUs in teh CPT
		 */
		nthrs = cfs_cpt_weight(lnet_cpt_table(), i);
		if (*ksocknal_tunables.ksnd_nscheds > 0) {
			nthrs = min(nthrs, *ksocknal_tunables.ksnd_nscheds);
		} else {
			/* max to half of CPUs, assume another half should be
			 * reserved for upper layer modules
			 */
			nthrs = min(max(SOCKNAL_NSCHEDS, nthrs >> 1), nthrs);
		}

		sched->kss_nthreads_max = nthrs;
		sched->kss_cpt = i;

		spin_lock_init(&sched->kss_lock);
		INIT_LIST_HEAD(&sched->kss_rx_conns);
		INIT_LIST_HEAD(&sched->kss_tx_conns);
		INIT_LIST_HEAD(&sched->kss_zombie_noop_txs);
		init_waitqueue_head(&sched->kss_waitq);
	}

	ksocknal_data.ksnd_connd_starting         = 0;
	ksocknal_data.ksnd_connd_failed_stamp     = 0;
	ksocknal_data.ksnd_connd_starting_stamp   = ktime_get_real_seconds();
	/* must have at least 2 connds to remain responsive to accepts while
	 * connecting
	 */
	if (*ksocknal_tunables.ksnd_nconnds < SOCKNAL_CONND_RESV + 1)
		*ksocknal_tunables.ksnd_nconnds = SOCKNAL_CONND_RESV + 1;

	if (*ksocknal_tunables.ksnd_nconnds_max <
	    *ksocknal_tunables.ksnd_nconnds) {
		ksocknal_tunables.ksnd_nconnds_max =
			ksocknal_tunables.ksnd_nconnds;
	}

	for (i = 0; i < *ksocknal_tunables.ksnd_nconnds; i++) {
		spin_lock_bh(&ksocknal_data.ksnd_connd_lock);
		ksocknal_data.ksnd_connd_starting++;
		spin_unlock_bh(&ksocknal_data.ksnd_connd_lock);

		rc = ksocknal_thread_start(ksocknal_connd,
					   (void *)((uintptr_t)i),
					   "socknal_cd%02d", i);
		if (rc != 0) {
			spin_lock_bh(&ksocknal_data.ksnd_connd_lock);
			ksocknal_data.ksnd_connd_starting--;
			spin_unlock_bh(&ksocknal_data.ksnd_connd_lock);
			CERROR("Can't spawn socknal connd: %d\n", rc);
			goto failed;
		}
	}

	rc = ksocknal_thread_start(ksocknal_reaper, NULL, "socknal_reaper");
	if (rc != 0) {
		CERROR("Can't spawn socknal reaper: %d\n", rc);
		goto failed;
	}

	register_netdevice_notifier(&ksocknal_dev_notifier_block);
	register_inetaddr_notifier(&ksocknal_inetaddr_notifier_block);
#if IS_ENABLED(CONFIG_IPV6)
	register_inet6addr_notifier(&ksocknal_inet6addr_notifier_block);
#endif
	/* flag everything initialised */
	ksocknal_data.ksnd_init = SOCKNAL_INIT_ALL;

	return 0;

failed:
	ksocknal_base_shutdown();
	return -ENETDOWN;
}

static int
ksocknal_debug_peerhash(struct lnet_ni *ni)
{
	struct ksock_peer_ni *peer_ni;
	int i;

	read_lock(&ksocknal_data.ksnd_global_lock);

	hash_for_each(ksocknal_data.ksnd_peers, i, peer_ni, ksnp_list) {
		struct ksock_conn_cb *conn_cb;
		struct ksock_conn *conn;

		if (peer_ni->ksnp_ni != ni)
			continue;

		CWARN("Active peer_ni on shutdown: %s, ref %d, closing %d, accepting %d, err %d, zcookie %llu, txq %d, zc_req %d\n",
		      libcfs_idstr(&peer_ni->ksnp_id),
		      refcount_read(&peer_ni->ksnp_refcount),
		      peer_ni->ksnp_closing,
		      peer_ni->ksnp_accepting, peer_ni->ksnp_error,
		      peer_ni->ksnp_zc_next_cookie,
		      !list_empty(&peer_ni->ksnp_tx_queue),
		      !list_empty(&peer_ni->ksnp_zc_req_list));

		conn_cb = peer_ni->ksnp_conn_cb;
		if (conn_cb) {
			CWARN("ConnCB: ref %d, schd %d, conn %d, cnted %d, del %d\n",
			      refcount_read(&conn_cb->ksnr_refcount),
			      conn_cb->ksnr_scheduled, conn_cb->ksnr_connecting,
			      conn_cb->ksnr_connected, conn_cb->ksnr_deleted);
		}

		list_for_each_entry(conn, &peer_ni->ksnp_conns, ksnc_list) {
			CWARN("Conn: ref %d, sref %d, t %d, c %d\n",
			      refcount_read(&conn->ksnc_conn_refcount),
			      refcount_read(&conn->ksnc_sock_refcount),
			      conn->ksnc_type, conn->ksnc_closing);
		}
		break;
	}

	read_unlock(&ksocknal_data.ksnd_global_lock);
	return 0;
}

void
ksocknal_shutdown(struct lnet_ni *ni)
{
	struct ksock_net *net = ni->ni_data;

	LASSERT(ksocknal_data.ksnd_init == SOCKNAL_INIT_ALL);
	LASSERT(ksocknal_data.ksnd_nnets > 0);

	/* prevent new peers */
	atomic_add(SOCKNAL_SHUTDOWN_BIAS, &net->ksnn_npeers);

	/* Delete all peers */
	ksocknal_del_peer(ni, NULL);

	/* Wait for all peer_ni state to clean up */
	wait_var_event_warning(&net->ksnn_npeers,
			       atomic_read(&net->ksnn_npeers) ==
			       SOCKNAL_SHUTDOWN_BIAS,
			       "waiting for %d peers to disconnect\n",
			       ksocknal_debug_peerhash(ni) +
			       atomic_read(&net->ksnn_npeers) -
			       SOCKNAL_SHUTDOWN_BIAS);

	LASSERT(net->ksnn_interface.ksni_npeers == 0);
	LASSERT(net->ksnn_interface.ksni_nroutes == 0);

	list_del(&net->ksnn_list);
	LIBCFS_FREE(net, sizeof(*net));

	ksocknal_data.ksnd_nnets--;
	if (ksocknal_data.ksnd_nnets == 0)
		ksocknal_base_shutdown();
}

static int
ksocknal_search_new_ipif(struct ksock_net *net)
{
	int new_ipif = 0;
	char *ifnam = &net->ksnn_interface.ksni_name[0];
	char *colon = strchr(ifnam, ':');
	bool found = false;
	struct ksock_net *tmp;

	if (colon != NULL)
		*colon = 0;

	list_for_each_entry(tmp, &ksocknal_data.ksnd_nets, ksnn_list) {
		char *ifnam2 = &tmp->ksnn_interface.ksni_name[0];
		char *colon2 = strchr(ifnam2, ':');

		if (colon2 != NULL)
			*colon2 = 0;

		found = strcmp(ifnam, ifnam2) == 0;
		if (colon2 != NULL)
			*colon2 = ':';
	}

	new_ipif += !found;
	if (colon != NULL)
		*colon = ':';

	return new_ipif;
}

static int
ksocknal_start_schedulers(struct ksock_sched *sched)
{
	int	nthrs;
	int	rc = 0;
	int	i;

	if (sched->kss_nthreads == 0) {
		if (*ksocknal_tunables.ksnd_nscheds > 0) {
			nthrs = sched->kss_nthreads_max;
		} else {
			nthrs = cfs_cpt_weight(lnet_cpt_table(),
					       sched->kss_cpt);
			nthrs = min(max(SOCKNAL_NSCHEDS, nthrs >> 1), nthrs);
			nthrs = min(SOCKNAL_NSCHEDS_HIGH, nthrs);
		}
		nthrs = min(nthrs, sched->kss_nthreads_max);
	} else {
		LASSERT(sched->kss_nthreads <= sched->kss_nthreads_max);
		/* increase two threads if there is new interface */
		nthrs = min(2, sched->kss_nthreads_max - sched->kss_nthreads);
	}

	for (i = 0; i < nthrs; i++) {
		long id;

		id = KSOCK_THREAD_ID(sched->kss_cpt, sched->kss_nthreads + i);
		rc = ksocknal_thread_start(ksocknal_scheduler, (void *)id,
					   "socknal_sd%02d_%02d",
					   sched->kss_cpt,
					   (int)KSOCK_THREAD_SID(id));
		if (rc == 0)
			continue;

		CERROR("Can't spawn thread %d for scheduler[%d]: %d\n",
		       sched->kss_cpt, (int) KSOCK_THREAD_SID(id), rc);
		break;
	}

	sched->kss_nthreads += i;
	return rc;
}

static int
ksocknal_net_start_threads(struct ksock_net *net, __u32 *cpts, int ncpts)
{
	int newif = ksocknal_search_new_ipif(net);
	int rc;
	int i;

	if (ncpts > 0 && ncpts > cfs_cpt_number(lnet_cpt_table()))
		return -EINVAL;

	for (i = 0; i < ncpts; i++) {
		struct ksock_sched *sched;
		int cpt = (cpts == NULL) ? i : cpts[i];

		LASSERT(cpt < cfs_cpt_number(lnet_cpt_table()));
		sched = ksocknal_data.ksnd_schedulers[cpt];

		if (!newif && sched->kss_nthreads > 0)
			continue;

		rc = ksocknal_start_schedulers(sched);
		if (rc != 0)
			return rc;
	}
	return 0;
}

int
ksocknal_startup(struct lnet_ni *ni)
{
	struct ksock_net *net;
	struct ksock_interface *ksi = NULL;
	struct lnet_inetdev *ifaces = NULL;
	int rc, if_idx;
	int dev_status;

	LASSERT(ni->ni_net->net_lnd == &the_ksocklnd);
	if (ksocknal_data.ksnd_init == SOCKNAL_INIT_NOTHING) {
		rc = ksocknal_base_startup();
		if (rc != 0)
			return rc;
	}
	LIBCFS_ALLOC(net, sizeof(*net));
	if (net == NULL)
		goto out_base;

	net->ksnn_incarnation = ktime_get_real_ns();
	ni->ni_data = net;

	ksocknal_tunables_setup(ni);

	rc = lnet_inet_enumerate(&ifaces, ni->ni_net_ns,
				 the_lnet.ln_nis_use_large_nids);
	if (rc < 0)
		goto out_net;

	ksi = &net->ksnn_interface;

	/* Interface and/or IP address is specified otherwise default to
	 * the first Interface
	 */
	if_idx = lnet_inet_select(ni, ifaces, rc);
	if (if_idx < 0)
		goto out_net;

	if (!ni->ni_interface || !strlen(ni->ni_interface)) {
		rc = lnet_ni_add_interface(ni, ifaces[if_idx].li_name);
		if (rc < 0)
			CWARN("ksocklnd failed to allocate ni_interface\n");
	}

	ni->ni_dev_cpt = ifaces[if_idx].li_cpt;
	ksi->ksni_index = ifaces[if_idx].li_index;
	if (ifaces[if_idx].li_size == sizeof(struct in6_addr)) {
		struct sockaddr_in6 *sa;

		sa = (void *)&ksi->ksni_addr;
		memset(sa, 0, sizeof(*sa));
		sa->sin6_family = AF_INET6;
		memcpy(&sa->sin6_addr, ifaces[if_idx].li_ipv6addr,
		       sizeof(struct in6_addr));
		ni->ni_nid.nid_size = sizeof(struct in6_addr) - 4;
		memcpy(&ni->ni_nid.nid_addr, ifaces[if_idx].li_ipv6addr,
		       sizeof(struct in6_addr));
	} else {
		struct sockaddr_in *sa;

		sa = (void *)&ksi->ksni_addr;
		memset(sa, 0, sizeof(*sa));
		sa->sin_family = AF_INET;
		sa->sin_addr.s_addr = ifaces[if_idx].li_ipaddr;
		ksi->ksni_netmask = ifaces[if_idx].li_netmask;
		ni->ni_nid.nid_size = 0;
		ni->ni_nid.nid_addr[0] = sa->sin_addr.s_addr;
	}
	strscpy(ksi->ksni_name, ifaces[if_idx].li_name, sizeof(ksi->ksni_name));

	/* call it before add it to ksocknal_data.ksnd_nets */
	rc = ksocknal_net_start_threads(net, ni->ni_cpts, ni->ni_ncpts);
	if (rc != 0)
		goto out_net;

	if ((ksocknal_ip2index((struct sockaddr *)&ksi->ksni_addr,
				ni,
				&dev_status) < 0) ||
	     (dev_status <= 0))
		lnet_set_link_fatal_state(ni, 1);

	list_add(&net->ksnn_list, &ksocknal_data.ksnd_nets);
	net->ksnn_ni = ni;
	ksocknal_data.ksnd_nnets++;
	kfree(ifaces);

	return 0;

out_net:
	LIBCFS_FREE(net, sizeof(*net));
out_base:
	if (ksocknal_data.ksnd_nnets == 0)
		ksocknal_base_shutdown();
	kfree(ifaces);

	return -ENETDOWN;
}

static void __exit ksocklnd_exit(void)
{
	lnet_unregister_lnd(&the_ksocklnd);
}

static const struct lnet_lnd the_ksocklnd = {
	.lnd_type		= SOCKLND,
	.lnd_startup		= ksocknal_startup,
	.lnd_shutdown		= ksocknal_shutdown,
	.lnd_ctl		= ksocknal_ctl,
	.lnd_send		= ksocknal_send,
	.lnd_recv		= ksocknal_recv,
	.lnd_notify_peer_down	= ksocknal_notify_gw_down,
	.lnd_accept		= ksocknal_accept,
	.lnd_nl_get		= ksocknal_nl_get,
	.lnd_nl_set		= ksocknal_nl_set,
	.lnd_keys		= &ksocknal_tunables_keys,
};

static int __init ksocklnd_init(void)
{
	int rc;

	/* check ksnr_connected/connecting field large enough */
	BUILD_BUG_ON(SOCKLND_CONN_NTYPES > 4);
	BUILD_BUG_ON(SOCKLND_CONN_ACK != SOCKLND_CONN_BULK_IN);

	rc = ksocknal_tunables_init();
	if (rc != 0)
		return rc;

	rc = libcfs_setup();
	if (rc)
		return rc;

	lnet_register_lnd(&the_ksocklnd);

	return 0;
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("TCP Socket LNet Network Driver");
MODULE_VERSION("2.8.0");
MODULE_LICENSE("GPL");

module_init(ksocklnd_init);
module_exit(ksocklnd_exit);
