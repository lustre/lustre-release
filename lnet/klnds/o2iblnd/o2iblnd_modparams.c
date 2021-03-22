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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/klnds/o2iblnd/o2iblnd_modparams.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "o2iblnd.h"

#define CURRENT_LND_VERSION 1

static int service = 987;
module_param(service, int, 0444);
MODULE_PARM_DESC(service, "service number (within RDMA_PS_TCP)");

static int cksum = 0;
module_param(cksum, int, 0644);
MODULE_PARM_DESC(cksum, "set non-zero to enable message (not RDMA) checksums");

static int timeout;
module_param(timeout, int, 0644);
MODULE_PARM_DESC(timeout, "timeout (seconds)");

/* Number of threads in each scheduler pool which is percpt,
 * we will estimate reasonable value based on CPUs if it's set to zero. */
static int nscheds;
module_param(nscheds, int, 0444);
MODULE_PARM_DESC(nscheds, "number of threads in each scheduler pool");

static unsigned int conns_per_peer = 1;
module_param(conns_per_peer, uint, 0444);
MODULE_PARM_DESC(conns_per_peer, "number of connections per peer");

/* NB: this value is shared by all CPTs, it can grow at runtime */
static int ntx = 512;
module_param(ntx, int, 0444);
MODULE_PARM_DESC(ntx, "# of message descriptors allocated for each pool");

/* NB: this value is shared by all CPTs */
static int credits = DEFAULT_CREDITS;
module_param(credits, int, 0444);
MODULE_PARM_DESC(credits, "# concurrent sends");

static int peer_credits = DEFAULT_PEER_CREDITS;
module_param(peer_credits, int, 0444);
MODULE_PARM_DESC(peer_credits, "# concurrent sends to 1 peer");

static int peer_credits_hiw = 0;
module_param(peer_credits_hiw, int, 0444);
MODULE_PARM_DESC(peer_credits_hiw, "when eagerly to return credits");

static int peer_buffer_credits = 0;
module_param(peer_buffer_credits, int, 0444);
MODULE_PARM_DESC(peer_buffer_credits, "# per-peer router buffer credits");

static int peer_timeout = DEFAULT_PEER_TIMEOUT;
module_param(peer_timeout, int, 0444);
MODULE_PARM_DESC(peer_timeout, "Seconds without aliveness news to declare peer dead (<=0 to disable)");

static char *ipif_name = "ib0";
module_param(ipif_name, charp, 0444);
MODULE_PARM_DESC(ipif_name, "IPoIB interface name");

static int retry_count = 5;
module_param(retry_count, int, 0644);
MODULE_PARM_DESC(retry_count, "Number of times to retry connection operations");

static int rnr_retry_count = 6;
module_param(rnr_retry_count, int, 0644);
MODULE_PARM_DESC(rnr_retry_count, "RNR retransmissions");

static int keepalive = 100;
module_param(keepalive, int, 0644);
MODULE_PARM_DESC(keepalive, "Idle time in seconds before sending a keepalive");

static int ib_mtu;
module_param(ib_mtu, int, 0444);
MODULE_PARM_DESC(ib_mtu, "IB MTU 256/512/1024/2048/4096");

static int concurrent_sends;
module_param(concurrent_sends, int, 0444);
MODULE_PARM_DESC(concurrent_sends, "send work-queue sizing");

static int use_fastreg_gaps;
module_param(use_fastreg_gaps, int, 0444);
MODULE_PARM_DESC(use_fastreg_gaps, "Enable discontiguous fastreg fragment support. Expect performance drop");

/*
 * map_on_demand is a flag used to determine if we can use FMR or FastReg.
 * This is applicable for kernels which support global memory regions. For
 * later kernels this flag is always enabled, since we will always either
 * use FMR or FastReg
 * For kernels which support global memory regions map_on_demand defaults
 * to 0 which means we will be using global memory regions exclusively.
 * If it is set to a value other than 0, then we will behave as follows:
 *  1. Always default the number of fragments to IBLND_MAX_RDMA_FRAGS
 *  2. Create FMR/FastReg pools
 *  3. Negotiate the supported number of fragments per connection
 *  4. Attempt to transmit using global memory regions only if
 *     map-on-demand is not turned on, otherwise use FMR or FastReg
 *  5. In case of transmitting tx with GAPS over FMR we will need to
 *     transmit it with multiple fragments. Look at the comments in
 *     kiblnd_fmr_map_tx() for an explanation of the behavior.
 *
 * For later kernels we default map_on_demand to 1 and not allow
 * it to be set to 0, since there is no longer support for global memory
 * regions. Behavior:
 *  1. Default the number of fragments to IBLND_MAX_RDMA_FRAGS
 *  2. Create FMR/FastReg pools
 *  3. Negotiate the supported number of fragments per connection
 *  4. Look at the comments in kiblnd_fmr_map_tx() for an explanation of
 *     the behavior when transmit with GAPS verses contiguous.
 */
#ifdef HAVE_IB_GET_DMA_MR
#define IBLND_DEFAULT_MAP_ON_DEMAND 0
#define MOD_STR "map on demand"
#else
#define IBLND_DEFAULT_MAP_ON_DEMAND 1
#define MOD_STR "map on demand (obsolete)"
#endif
static int map_on_demand = IBLND_DEFAULT_MAP_ON_DEMAND;
module_param(map_on_demand, int, 0444);
MODULE_PARM_DESC(map_on_demand, MOD_STR);

/* NB: this value is shared by all CPTs, it can grow at runtime */
static int fmr_pool_size = 512;
module_param(fmr_pool_size, int, 0444);
MODULE_PARM_DESC(fmr_pool_size, "size of fmr pool on each CPT (>= ntx / 4)");

/* NB: this value is shared by all CPTs, it can grow at runtime */
static int fmr_flush_trigger = 384;
module_param(fmr_flush_trigger, int, 0444);
MODULE_PARM_DESC(fmr_flush_trigger, "# dirty FMRs that triggers pool flush");

static int fmr_cache = 1;
module_param(fmr_cache, int, 0444);
MODULE_PARM_DESC(fmr_cache, "non-zero to enable FMR caching");

/*
 * 0: disable failover
 * 1: enable failover if necessary
 * 2: force to failover (for debug)
 */
static int dev_failover = 0;
module_param(dev_failover, int, 0444);
MODULE_PARM_DESC(dev_failover, "HCA failover for bonding (0 off, 1 on, other values reserved)");

static int require_privileged_port;
module_param(require_privileged_port, int, 0644);
MODULE_PARM_DESC(require_privileged_port, "require privileged port when accepting connection");

static int use_privileged_port = 1;
module_param(use_privileged_port, int, 0644);
MODULE_PARM_DESC(use_privileged_port, "use privileged port when initiating connection");

static unsigned int wrq_sge = 2;
module_param(wrq_sge, uint, 0444);
MODULE_PARM_DESC(wrq_sge, "# scatter/gather element per work request");

struct kib_tunables kiblnd_tunables = {
        .kib_dev_failover           = &dev_failover,
        .kib_service                = &service,
        .kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_keepalive              = &keepalive,
        .kib_default_ipif           = &ipif_name,
        .kib_retry_count            = &retry_count,
        .kib_rnr_retry_count        = &rnr_retry_count,
        .kib_ib_mtu                 = &ib_mtu,
        .kib_require_priv_port      = &require_privileged_port,
	.kib_use_priv_port	    = &use_privileged_port,
	.kib_nscheds		    = &nscheds,
	.kib_wrq_sge		    = &wrq_sge,
	.kib_use_fastreg_gaps       = &use_fastreg_gaps,
};

static struct lnet_ioctl_config_o2iblnd_tunables default_tunables;

/* # messages/RDMAs in-flight */
int
kiblnd_msg_queue_size(int version, struct lnet_ni *ni)
{
	if (version == IBLND_MSG_VERSION_1)
		return IBLND_MSG_QUEUE_SIZE_V1;
	else if (ni)
		return ni->ni_net->net_tunables.lct_peer_tx_credits;
	else
		return peer_credits;
}

int
kiblnd_tunables_setup(struct lnet_ni *ni)
{
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;
	struct lnet_ioctl_config_lnd_cmn_tunables *net_tunables;

	/*
	 * if there was no tunables specified, setup the tunables to be
	 * defaulted
	 */
	if (!ni->ni_lnd_tunables_set)
		memcpy(&ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib,
		       &default_tunables, sizeof(*tunables));

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;

	/* Current API version */
	tunables->lnd_version = CURRENT_LND_VERSION;

	if (*kiblnd_tunables.kib_ib_mtu &&
	    ib_mtu_enum_to_int(ib_mtu_int_to_enum(*kiblnd_tunables.kib_ib_mtu)) !=
	    *kiblnd_tunables.kib_ib_mtu) {
		CERROR("Invalid ib_mtu %d, expected 256/512/1024/2048/4096\n",
		       *kiblnd_tunables.kib_ib_mtu);
		return -EINVAL;
	}

	net_tunables = &ni->ni_net->net_tunables;

	if (net_tunables->lct_peer_timeout == -1)
		net_tunables->lct_peer_timeout = peer_timeout;

	if (net_tunables->lct_max_tx_credits == -1)
		net_tunables->lct_max_tx_credits = credits;

	if (net_tunables->lct_peer_tx_credits == -1)
		net_tunables->lct_peer_tx_credits = peer_credits;

	if (net_tunables->lct_peer_rtr_credits == -1)
		net_tunables->lct_peer_rtr_credits = peer_buffer_credits;

	if (net_tunables->lct_peer_tx_credits < IBLND_CREDITS_DEFAULT)
		net_tunables->lct_peer_tx_credits = IBLND_CREDITS_DEFAULT;

	if (net_tunables->lct_peer_tx_credits > IBLND_CREDITS_MAX)
		net_tunables->lct_peer_tx_credits = IBLND_CREDITS_MAX;

	if (net_tunables->lct_peer_tx_credits >
	    net_tunables->lct_max_tx_credits)
		net_tunables->lct_peer_tx_credits =
			net_tunables->lct_max_tx_credits;

#ifndef HAVE_IB_GET_DMA_MR
	/*
	 * For kernels which do not support global memory regions, always
	 * enable map_on_demand
	 */
	if (tunables->lnd_map_on_demand == 0)
		tunables->lnd_map_on_demand = 1;
#endif

	if (!tunables->lnd_peercredits_hiw)
		tunables->lnd_peercredits_hiw = peer_credits_hiw;

	if (tunables->lnd_peercredits_hiw < net_tunables->lct_peer_tx_credits / 2)
		tunables->lnd_peercredits_hiw = net_tunables->lct_peer_tx_credits / 2;

	if (tunables->lnd_peercredits_hiw >= net_tunables->lct_peer_tx_credits)
		tunables->lnd_peercredits_hiw = net_tunables->lct_peer_tx_credits - 1;

	if (tunables->lnd_concurrent_sends == 0)
			tunables->lnd_concurrent_sends = net_tunables->lct_peer_tx_credits;

	if (tunables->lnd_concurrent_sends > net_tunables->lct_peer_tx_credits * 2)
		tunables->lnd_concurrent_sends = net_tunables->lct_peer_tx_credits * 2;

	if (tunables->lnd_concurrent_sends < net_tunables->lct_peer_tx_credits / 2)
		tunables->lnd_concurrent_sends = net_tunables->lct_peer_tx_credits / 2;

	if (tunables->lnd_concurrent_sends < net_tunables->lct_peer_tx_credits) {
		CWARN("Concurrent sends %d is lower than message "
		      "queue size: %d, performance may drop slightly.\n",
		      tunables->lnd_concurrent_sends,
		      net_tunables->lct_peer_tx_credits);
	}

	if (!tunables->lnd_fmr_pool_size)
		tunables->lnd_fmr_pool_size = fmr_pool_size;
	if (!tunables->lnd_fmr_flush_trigger)
		tunables->lnd_fmr_flush_trigger = fmr_flush_trigger;
	if (!tunables->lnd_fmr_cache)
		tunables->lnd_fmr_cache = fmr_cache;
	if (!tunables->lnd_ntx)
		tunables->lnd_ntx = ntx;
	if (!tunables->lnd_conns_per_peer) {
		tunables->lnd_conns_per_peer = (conns_per_peer) ?
			conns_per_peer : 1;
	}

	return 0;
}

int
kiblnd_tunables_init(void)
{
	default_tunables.lnd_version = CURRENT_LND_VERSION;
	default_tunables.lnd_peercredits_hiw = peer_credits_hiw;
	default_tunables.lnd_map_on_demand = map_on_demand;
	default_tunables.lnd_concurrent_sends = concurrent_sends;
	default_tunables.lnd_fmr_pool_size = fmr_pool_size;
	default_tunables.lnd_fmr_flush_trigger = fmr_flush_trigger;
	default_tunables.lnd_fmr_cache = fmr_cache;
	default_tunables.lnd_ntx = ntx;
	default_tunables.lnd_conns_per_peer = conns_per_peer;
	return 0;
}
