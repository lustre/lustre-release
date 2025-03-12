// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2023-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Yehuda Yitschak <yehuday@amazon.com>
 * Author: Yonatan Nachum <ynachum@amazon.com>
 */

#include "efalnd.h"

/* Number of threads in each scheduler pool which is percpt,
 * we will estimate reasonable value based on CPUs if it's set to zero.
 */
static int nscheds;
module_param(nscheds, int, 0444);
MODULE_PARM_DESC(nscheds, "number of threads in each scheduler pool");

/* Number of QPs each device allocates. */
static int nqps = 8;
module_param(nqps, int, 0444);
MODULE_PARM_DESC(nqps, "number of QPs each device allocates");

/* NB: this value is shared by all CPTs */
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

/* Infiniband spec for RNR values:
 * 0-6: Exact number of retries
 * 7: Infinite RNR
 */
static int rnr_retry_count = 7;
module_param(rnr_retry_count, int, 0644);
MODULE_PARM_DESC(rnr_retry_count, "RNR retransmissions");

static char *ipif_name;
module_param(ipif_name, charp, 0444);
MODULE_PARM_DESC(ipif_name, "Ethernet interface name");

struct kefa_tunables kefalnd_tunables = {
	.kefa_rnr_retry_count	     = &rnr_retry_count,
	.kefa_nscheds		     = &nscheds,
	.kefa_ipif_name		     = &ipif_name,
};

static struct lnet_ioctl_config_efalnd_tunables default_tunables;

int
kefalnd_tunables_setup(struct lnet_ni *ni)
{
	struct lnet_ioctl_config_efalnd_tunables *tunables;
	struct lnet_ioctl_config_lnd_cmn_tunables *net_tunables;

	/*
	 * if there was no tunables specified, setup the tunables to be
	 * defaulted
	 */
	if (!ni->ni_lnd_tunables_set)
		memcpy(&ni->ni_lnd_tunables.lnd_tun_u.lnd_efa,
		       &default_tunables, sizeof(*tunables));

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_efa;

	/* Current LND version */
	tunables->lnd_version = kefalnd_get_lnd_version();

	net_tunables = &ni->ni_net->net_tunables;

	if (net_tunables->lct_peer_timeout == -1)
		net_tunables->lct_peer_timeout = peer_timeout;

	if (net_tunables->lct_max_tx_credits == -1)
		net_tunables->lct_max_tx_credits = credits;

	if (net_tunables->lct_peer_tx_credits == -1)
		net_tunables->lct_peer_tx_credits = peer_credits;

	if (net_tunables->lct_peer_rtr_credits == -1)
		net_tunables->lct_peer_rtr_credits = peer_buffer_credits;

	if (net_tunables->lct_peer_tx_credits < EFALND_CREDITS_MIN)
		net_tunables->lct_peer_tx_credits = EFALND_CREDITS_MIN;

	if (net_tunables->lct_peer_tx_credits > EFALND_CREDITS_MAX)
		net_tunables->lct_peer_tx_credits = EFALND_CREDITS_MAX;

	if (net_tunables->lct_peer_timeout < EFALND_MIN_INIT_CONN_TIMEOUT)
		net_tunables->lct_peer_timeout = EFALND_MIN_INIT_CONN_TIMEOUT;

	if (net_tunables->lct_peer_tx_credits >
	    net_tunables->lct_max_tx_credits)
		net_tunables->lct_peer_tx_credits =
			net_tunables->lct_max_tx_credits;

	if (!tunables->lnd_nqps)
		tunables->lnd_nqps = nqps;

	return 0;
}

int
kefalnd_tunables_init(void)
{
	default_tunables.lnd_version = kefalnd_get_lnd_version();
	default_tunables.lnd_nqps = nqps;
	return 0;
}
