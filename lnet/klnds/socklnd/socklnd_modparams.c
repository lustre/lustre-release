/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 *
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "socklnd.h"

#include <linux/kvm_host.h>
#if defined(__x86_64__) || defined(__i386__)
#include <asm/hypervisor.h>
#endif
#ifdef HAVE_ETHTOOL_LINK_SETTINGS
#include <linux/inetdevice.h>
#include <linux/ethtool.h>
#endif

#define CURRENT_LND_VERSION 1

static int sock_timeout;
module_param(sock_timeout, int, 0644);
MODULE_PARM_DESC(sock_timeout, "dead socket timeout (seconds)");

static int credits = DEFAULT_CREDITS;
module_param(credits, int, 0444);
MODULE_PARM_DESC(credits, "# concurrent sends");

static int peer_credits = DEFAULT_PEER_CREDITS;
module_param(peer_credits, int, 0444);
MODULE_PARM_DESC(peer_credits, "# concurrent sends to 1 peer");

static int peer_buffer_credits;
module_param(peer_buffer_credits, int, 0444);
MODULE_PARM_DESC(peer_buffer_credits, "# per-peer router buffer credits");

static int peer_timeout = DEFAULT_PEER_TIMEOUT;
module_param(peer_timeout, int, 0444);
MODULE_PARM_DESC(peer_timeout, "Seconds without aliveness news to declare peer dead (<=0 to disable)");

/* Number of daemons in each thread pool which is percpt,
 * we will estimate reasonable value based on CPUs if it's not set. */
static unsigned int nscheds;
module_param(nscheds, int, 0444);
MODULE_PARM_DESC(nscheds, "# scheduler daemons in each pool while starting");

static int nconnds = 4;
module_param(nconnds, int, 0444);
MODULE_PARM_DESC(nconnds, "# connection daemons while starting");

static int nconnds_max = 64;
module_param(nconnds_max, int, 0444);
MODULE_PARM_DESC(nconnds_max, "max # connection daemons");

static int min_reconnectms = 1000;
module_param(min_reconnectms, int, 0644);
MODULE_PARM_DESC(min_reconnectms, "min connection retry interval (mS)");

static int max_reconnectms = 60000;
module_param(max_reconnectms, int, 0644);
MODULE_PARM_DESC(max_reconnectms, "max connection retry interval (mS)");

static int eager_ack;
module_param(eager_ack, int, 0644);
MODULE_PARM_DESC(eager_ack, "send tcp ack packets eagerly");

static int typed_conns = 1;
module_param(typed_conns, int, 0444);
MODULE_PARM_DESC(typed_conns, "use different sockets for bulk");

static int min_bulk = (1<<10);
module_param(min_bulk, int, 0644);
MODULE_PARM_DESC(min_bulk, "smallest 'large' message");

# define DEFAULT_BUFFER_SIZE 0
static int tx_buffer_size = DEFAULT_BUFFER_SIZE;
module_param(tx_buffer_size, int, 0644);
MODULE_PARM_DESC(tx_buffer_size, "socket tx buffer size (0 for system default)");

static int rx_buffer_size = DEFAULT_BUFFER_SIZE;
module_param(rx_buffer_size, int, 0644);
MODULE_PARM_DESC(rx_buffer_size, "socket rx buffer size (0 for system default)");

static int nagle = 0;
module_param(nagle, int, 0644);
MODULE_PARM_DESC(nagle, "enable NAGLE?");

static int round_robin = 1;
module_param(round_robin, int, 0644);
MODULE_PARM_DESC(round_robin, "Round robin for multiple interfaces");

static int keepalive = 30;
module_param(keepalive, int, 0644);
MODULE_PARM_DESC(keepalive, "# seconds before send keepalive");

static int keepalive_idle = 30;
module_param(keepalive_idle, int, 0644);
MODULE_PARM_DESC(keepalive_idle, "# idle seconds before probe");

#define DEFAULT_KEEPALIVE_COUNT  5
static int keepalive_count = DEFAULT_KEEPALIVE_COUNT;
module_param(keepalive_count, int, 0644);
MODULE_PARM_DESC(keepalive_count, "# missed probes == dead");

static int keepalive_intvl = 5;
module_param(keepalive_intvl, int, 0644);
MODULE_PARM_DESC(keepalive_intvl, "seconds between probes");

static int enable_csum = 0;
module_param(enable_csum, int, 0644);
MODULE_PARM_DESC(enable_csum, "enable check sum");

static int inject_csum_error = 0;
module_param(inject_csum_error, int, 0644);
MODULE_PARM_DESC(inject_csum_error, "set non-zero to inject a checksum error");

static int enable_irq_affinity = 0;
module_param(enable_irq_affinity, int, 0644);
MODULE_PARM_DESC(enable_irq_affinity, "enable IRQ affinity");

static int nonblk_zcack = 1;
module_param(nonblk_zcack, int, 0644);
MODULE_PARM_DESC(nonblk_zcack, "always send ZC-ACK on non-blocking connection");

static unsigned int zc_min_payload = (16 << 10);
module_param(zc_min_payload, int, 0644);
MODULE_PARM_DESC(zc_min_payload, "minimum payload size to zero copy");

static unsigned int zc_recv = 0;
module_param(zc_recv, int, 0644);
MODULE_PARM_DESC(zc_recv, "enable ZC recv for Chelsio driver");

static unsigned int zc_recv_min_nfrags = 16;
module_param(zc_recv_min_nfrags, int, 0644);
MODULE_PARM_DESC(zc_recv_min_nfrags, "minimum # of fragments to enable ZC recv");

static unsigned int conns_per_peer = DEFAULT_CONNS_PER_PEER;
module_param(conns_per_peer, uint, 0644);
MODULE_PARM_DESC(conns_per_peer, "number of connections per peer");

#ifdef SOCKNAL_BACKOFF
static int backoff_init = 3;
module_param(backoff_init, int, 0644);
MODULE_PARM_DESC(backoff_init, "seconds for initial tcp backoff");

static int backoff_max = 3;
module_param(backoff_max, int, 0644);
MODULE_PARM_DESC(backoff_max, "seconds for maximum tcp backoff");
#endif

#if SOCKNAL_VERSION_DEBUG
static int protocol = 3;
module_param(protocol, int, 0644);
MODULE_PARM_DESC(protocol, "protocol version");
#endif

static inline bool is_native_host(void)
{
#ifdef HAVE_HYPERVISOR_IS_TYPE
	return hypervisor_is_type(X86_HYPER_NATIVE);
#elif defined(__x86_64__) || defined(__i386__)
	return x86_hyper == NULL;
#else
	return true;
#endif
}

struct ksock_tunables ksocknal_tunables;
static struct lnet_ioctl_config_socklnd_tunables default_tunables;

#ifdef HAVE_ETHTOOL_LINK_SETTINGS
static int ksocklnd_ni_get_eth_intf_speed(struct lnet_ni *ni)
{
	struct net_device *dev;
	int intf_idx = -1;
	int ret = -1;

	DECLARE_CONST_IN_IFADDR(ifa);

	/* check if ni has interface assigned */
	if (!ni->ni_net_ns || !ni->ni_interface)
		return 0;

	rtnl_lock();
	for_each_netdev(ni->ni_net_ns, dev) {
		int flags = dev_get_flags(dev);
		struct in_device *in_dev;

		if (flags & IFF_LOOPBACK) /* skip the loopback IF */
			continue;

		if (!(flags & IFF_UP))
			continue;

		in_dev = __in_dev_get_rcu(dev);
		if (!in_dev)
			continue;

		in_dev_for_each_ifa_rcu(ifa, in_dev) {
			if (strcmp(ifa->ifa_label, ni->ni_interface) == 0)
				intf_idx = dev->ifindex;
		}
		endfor_ifa(in_dev);

		if (intf_idx >= 0)
			break;
	}
	if (intf_idx >= 0) {
		struct ethtool_link_ksettings cmd;
		int ethtool_ret;

		/* Some devices may not be providing link settings */
		ethtool_ret = __ethtool_get_link_ksettings(dev, &cmd);
		if (!ethtool_ret)
			ret = cmd.base.speed;
		else
			ret = ethtool_ret;
	}
	rtnl_unlock();

	return ret;
}

static int ksocklnd_speed2cpp(int speed)
{
	/* Use the minimum of 1Gbps to avoid calling ilog2 with 0 */
	if (speed < 1000)
		speed = 1000;

	/* Pick heuristically optimal conns_per_peer value
	 * for the specified ethernet interface speed (Mbps)
	 */
	return ilog2(speed/1000) / 2 + 1;
}
#endif

static int ksocklnd_lookup_conns_per_peer(struct lnet_ni *ni)
{
	int cpp = 1;
#ifdef HAVE_ETHTOOL_LINK_SETTINGS
	int speed = ksocklnd_ni_get_eth_intf_speed(ni);

	if (ni->ni_interface)
		CDEBUG(D_NET, "intf %s speed %d\n", ni->ni_interface, speed);

	if (speed > 0)
		cpp = ksocklnd_speed2cpp(speed);
#endif
	return cpp;
}

int ksocknal_tunables_init(void)
{
	default_tunables.lnd_version = CURRENT_LND_VERSION;
	default_tunables.lnd_conns_per_peer = conns_per_peer;

	/* initialize ksocknal_tunables structure */
	ksocknal_tunables.ksnd_timeout            = &sock_timeout;
	ksocknal_tunables.ksnd_nscheds		  = &nscheds;
	ksocknal_tunables.ksnd_nconnds            = &nconnds;
	ksocknal_tunables.ksnd_nconnds_max        = &nconnds_max;
	ksocknal_tunables.ksnd_min_reconnectms    = &min_reconnectms;
	ksocknal_tunables.ksnd_max_reconnectms    = &max_reconnectms;
	ksocknal_tunables.ksnd_eager_ack          = &eager_ack;
	ksocknal_tunables.ksnd_typed_conns        = &typed_conns;
	ksocknal_tunables.ksnd_min_bulk           = &min_bulk;
	ksocknal_tunables.ksnd_tx_buffer_size     = &tx_buffer_size;
	ksocknal_tunables.ksnd_rx_buffer_size     = &rx_buffer_size;
	ksocknal_tunables.ksnd_nagle              = &nagle;
	ksocknal_tunables.ksnd_round_robin        = &round_robin;
	ksocknal_tunables.ksnd_keepalive          = &keepalive;
	ksocknal_tunables.ksnd_keepalive_idle     = &keepalive_idle;
	ksocknal_tunables.ksnd_keepalive_count    = &keepalive_count;
	ksocknal_tunables.ksnd_keepalive_intvl    = &keepalive_intvl;
	ksocknal_tunables.ksnd_credits            = &credits;
	ksocknal_tunables.ksnd_peertxcredits      = &peer_credits;
	ksocknal_tunables.ksnd_peerrtrcredits     = &peer_buffer_credits;
	ksocknal_tunables.ksnd_peertimeout        = &peer_timeout;
	ksocknal_tunables.ksnd_enable_csum        = &enable_csum;
	ksocknal_tunables.ksnd_inject_csum_error  = &inject_csum_error;
	ksocknal_tunables.ksnd_nonblk_zcack       = &nonblk_zcack;
	ksocknal_tunables.ksnd_zc_min_payload     = &zc_min_payload;
	ksocknal_tunables.ksnd_zc_recv            = &zc_recv;
	ksocknal_tunables.ksnd_zc_recv_min_nfrags = &zc_recv_min_nfrags;
	if (conns_per_peer > ((1 << SOCKNAL_CONN_COUNT_MAX_BITS)-1)) {
		CWARN("socklnd conns_per_peer is capped at %u.\n",
		      (1 << SOCKNAL_CONN_COUNT_MAX_BITS)-1);
	}
	ksocknal_tunables.ksnd_conns_per_peer     = &conns_per_peer;

	if (enable_irq_affinity) {
		CWARN("irq_affinity is removed from socklnd because modern "
		      "computer always has fast CPUs and more cores than "
		      "# NICs, although you still can set irq_affinity by "
		      "another way, please check manual for details.\n");
	}
	ksocknal_tunables.ksnd_irq_affinity       = &enable_irq_affinity;

#ifdef SOCKNAL_BACKOFF
	ksocknal_tunables.ksnd_backoff_init       = &backoff_init;
	ksocknal_tunables.ksnd_backoff_max        = &backoff_max;
#endif

#if SOCKNAL_VERSION_DEBUG
	ksocknal_tunables.ksnd_protocol           = &protocol;
#endif

	if (*ksocknal_tunables.ksnd_zc_min_payload < (2 << 10))
		*ksocknal_tunables.ksnd_zc_min_payload = (2 << 10);

	/* When on a hypervisor set the minimum zero copy size
	 * above the maximum payload size
	 */
	if (!is_native_host())
		*ksocknal_tunables.ksnd_zc_min_payload = (16 << 20) + 1;

	return 0;
}

void ksocknal_tunables_setup(struct lnet_ni *ni)
{
	struct lnet_ioctl_config_socklnd_tunables *tunables;
	struct lnet_ioctl_config_lnd_cmn_tunables *net_tunables;

	/* If no tunables specified, setup default tunables */
	if (!ni->ni_lnd_tunables_set)
		memcpy(&ni->ni_lnd_tunables.lnd_tun_u.lnd_sock,
		       &default_tunables, sizeof(*tunables));

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_sock;

	/* Current API version */
	tunables->lnd_version = CURRENT_LND_VERSION;

	net_tunables = &ni->ni_net->net_tunables;

	if (net_tunables->lct_peer_timeout == -1)
		net_tunables->lct_peer_timeout =
			*ksocknal_tunables.ksnd_peertimeout;

	if (net_tunables->lct_max_tx_credits == -1)
		net_tunables->lct_max_tx_credits =
			*ksocknal_tunables.ksnd_credits;

	if (net_tunables->lct_peer_tx_credits == -1)
		net_tunables->lct_peer_tx_credits =
			*ksocknal_tunables.ksnd_peertxcredits;

	if (net_tunables->lct_peer_tx_credits >
	    net_tunables->lct_max_tx_credits)
		net_tunables->lct_peer_tx_credits =
			net_tunables->lct_max_tx_credits;

	if (net_tunables->lct_peer_rtr_credits == -1)
		net_tunables->lct_peer_rtr_credits =
			*ksocknal_tunables.ksnd_peerrtrcredits;

	if (!tunables->lnd_conns_per_peer)
		tunables->lnd_conns_per_peer =
			ksocklnd_lookup_conns_per_peer(ni);
}
