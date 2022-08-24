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
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * kfilnd module parameters
 */

#include "kfilnd.h"

unsigned int cksum;
module_param(cksum, uint, 0444);
MODULE_PARM_DESC(cksum, "Enable checksums for non-zero messages (not RDMA)");

/* Scale factor for TX context queue depth. The factor is applied to the number
 * of credits to determine queue depth.
 */
unsigned int tx_scale_factor = 2;
module_param(tx_scale_factor, uint, 0444);
MODULE_PARM_DESC(tx_scale_factor,
		 "Factor applied to credits to determine TX context size");

/* Scale factor for TX and RX completion queue depth. The factor is applied to
 * the number of credits to determine queue depth.
 */
unsigned int rx_cq_scale_factor = 10;
module_param(rx_cq_scale_factor, uint, 0444);
MODULE_PARM_DESC(rx_cq_scale_factor,
		 "Factor applied to credits to determine RX CQ size");

unsigned int tx_cq_scale_factor = 10;
module_param(tx_cq_scale_factor, uint, 0444);
MODULE_PARM_DESC(tx_cq_scale_factor,
		 "Factor applied to credits to determine TX CQ size");

unsigned int eq_size = 1024;
module_param(eq_size, uint, 0444);
MODULE_PARM_DESC(eq_size, "Default event queue size used by all kfi LNet NIs");

unsigned int immediate_rx_buf_count = 8;
module_param(immediate_rx_buf_count, uint, 0444);
MODULE_PARM_DESC(immediate_rx_buf_count,
		 "Number of immediate multi-receive buffers posted per CPT");

/* Common LND network tunables. */
static int credits = 256;
module_param(credits, int, 0444);
MODULE_PARM_DESC(credits, "Number of concurrent sends on network");

static int peer_credits = 16;
module_param(peer_credits, int, 0444);
MODULE_PARM_DESC(peer_credits, "Number of concurrent sends to 1 peer");

static int peer_buffer_credits = -1;
module_param(peer_buffer_credits, int, 0444);
MODULE_PARM_DESC(peer_buffer_credits,
		 "Number of per-peer router buffer credits");

static int peer_timeout = -1;
module_param(peer_timeout, int, 0444);
MODULE_PARM_DESC(peer_timeout,
		 "Seconds without aliveness news to declare peer dead (less than or equal to 0 to disable).");

static unsigned int prov_major_version = 1;
module_param(prov_major_version, int, 0444);
MODULE_PARM_DESC(prov_major_version,
		 "Default kfabric provider major version kfilnd should use");

static unsigned int prov_minor_version;
module_param(prov_minor_version, int, 0444);
MODULE_PARM_DESC(prov_minor_version,
		 "Default kfabric provider minor version kfilnd should use");

static unsigned int auth_key = 255;
module_param(auth_key, uint, 0444);
MODULE_PARM_DESC(auth_key, "Default authorization key to be used for LNet NIs");

int kfilnd_tunables_setup(struct lnet_ni *ni)
{
	struct lnet_ioctl_config_lnd_cmn_tunables *net_tunables;
	struct lnet_ioctl_config_kfilnd_tunables *kfilnd_tunables;

	net_tunables = &ni->ni_net->net_tunables;
	kfilnd_tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_kfi;

	if (net_tunables->lct_peer_timeout == -1)
		net_tunables->lct_peer_timeout = peer_timeout;

	if (net_tunables->lct_max_tx_credits == -1)
		net_tunables->lct_max_tx_credits = credits;

	if (net_tunables->lct_peer_tx_credits == -1)
		net_tunables->lct_peer_tx_credits = peer_credits;

	if (net_tunables->lct_peer_rtr_credits == -1)
		net_tunables->lct_peer_rtr_credits = peer_buffer_credits;

	if (net_tunables->lct_peer_tx_credits >
		net_tunables->lct_max_tx_credits)
		net_tunables->lct_peer_tx_credits =
			net_tunables->lct_max_tx_credits;

	kfilnd_tunables->lnd_version = KFILND_MSG_VERSION;
	if (!ni->ni_lnd_tunables_set) {
		kfilnd_tunables->lnd_prov_major_version = prov_major_version;
		kfilnd_tunables->lnd_prov_minor_version = prov_minor_version;
		kfilnd_tunables->lnd_auth_key = auth_key;
	}

	/* Treat kfilnd_tunables set to zero as uninitialized. */
	if (kfilnd_tunables->lnd_prov_major_version == 0 &&
		kfilnd_tunables->lnd_prov_major_version == 0) {
		kfilnd_tunables->lnd_prov_major_version = prov_major_version;
		kfilnd_tunables->lnd_prov_minor_version = prov_minor_version;
	}

	if (kfilnd_tunables->lnd_auth_key == 0)
		kfilnd_tunables->lnd_auth_key = auth_key;

	if (net_tunables->lct_max_tx_credits > KFILND_EP_KEY_MAX) {
		CERROR("Credits cannot exceed %lu\n", KFILND_EP_KEY_MAX);
		return -EINVAL;
	}

	if (net_tunables->lct_peer_tx_credits > KFILND_EP_KEY_MAX) {
		CERROR("Peer credits cannot exceed %lu\n", KFILND_EP_KEY_MAX);
		return -EINVAL;
	}

	if (kfilnd_tunables->lnd_prov_major_version > prov_major_version) {
		CERROR("Provider major version greater than %d unsupported\n",
			prov_major_version);
		return -EINVAL;
	}

	return 0;
}

int kfilnd_tunables_init(void)
{
	if (tx_scale_factor < 1) {
		CERROR("TX context scale factor less than 1");
		return -EINVAL;
	}

	if (rx_cq_scale_factor < 1) {
		CERROR("RX CQ scale factor less than 1");
		return -EINVAL;
	}

	if (tx_cq_scale_factor < 1) {
		CERROR("TX CQ scale factor less than 1");
		return -EINVAL;
	}

	if (immediate_rx_buf_count < 2) {
		CERROR("Immediate multi-receive buffer count less than 2");
		return -EINVAL;
	}

	if (auth_key < 1) {
		CERROR("Authorization key cannot be less than 1");
		return -EINVAL;
	}

	if (credits > KFILND_EP_KEY_MAX) {
		CERROR("Credits cannot exceed %lu\n", KFILND_EP_KEY_MAX);
		return -EINVAL;
	}

	if (peer_credits > KFILND_EP_KEY_MAX) {
		CERROR("Peer credits cannot exceed %lu\n", KFILND_EP_KEY_MAX);
		return -EINVAL;
	}

	return 0;
}
