// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
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

unsigned int prov_cpu_exclusive;
module_param(prov_cpu_exclusive, uint, 0644);
MODULE_PARM_DESC(prov_cpu_exclusive,
		 "Enables kfabric provider exclusive use of CPT's base CPU. Disabled by default. Set > 0 to enable.");

unsigned int wq_high_priority = 1;
module_param(wq_high_priority, uint, 0444);
MODULE_PARM_DESC(wq_high_priority,
		 "Enables work queue to run at high priority. Enabled by default. Set > 0 to enable.");

unsigned int wq_cpu_intensive;
module_param(wq_cpu_intensive, uint, 0444);
MODULE_PARM_DESC(wq_cpu_intensive,
		 "Marks work queue as CPU intensive. Disabled by default. Set > 0 to enable.");

unsigned int wq_max_active = 512;
module_param(wq_max_active, uint, 0444);
MODULE_PARM_DESC(wq_max_active,
		 "Max work queue work items active per CPU. Default is 512. Valid values 0 to 512.");

/* Common LND network tunables. */
static int credits = 512;
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

static char *traffic_class = "best_effort";
module_param(traffic_class, charp, 0444);
MODULE_PARM_DESC(traffic_class, "Traffic class - default is \"best_effort\"");

static int
kfilnd_tcstr2num(char *tcstr)
{
	if (!strcmp(tcstr, "best_effort"))
		return KFI_TC_BEST_EFFORT;
	if (!strcmp(tcstr, "low_latency"))
		return KFI_TC_LOW_LATENCY;
	if (!strcmp(tcstr, "dedicated_access"))
		return KFI_TC_DEDICATED_ACCESS;
	if (!strcmp(tcstr, "bulk_data"))
		return KFI_TC_BULK_DATA;
	if (!strcmp(tcstr, "scavenger"))
		return KFI_TC_SCAVENGER;
	if (!strcmp(tcstr, "network_ctrl"))
		return KFI_TC_NETWORK_CTRL;
	return -1;
}

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
		if (strlen(traffic_class) < LNET_MAX_STR_LEN)
			strcpy(&kfilnd_tunables->lnd_traffic_class_str[0],
			       traffic_class);
	}

	/* Treat kfilnd_tunables set to zero as uninitialized. */
	if (kfilnd_tunables->lnd_prov_major_version == 0 &&
		kfilnd_tunables->lnd_prov_major_version == 0) {
		kfilnd_tunables->lnd_prov_major_version = prov_major_version;
		kfilnd_tunables->lnd_prov_minor_version = prov_minor_version;
	}

	if (kfilnd_tunables->lnd_auth_key == 0)
		kfilnd_tunables->lnd_auth_key = auth_key;

	if (strlen(kfilnd_tunables->lnd_traffic_class_str) == 0 &&
	    strlen(traffic_class) < LNET_MAX_STR_LEN)
		strcpy(&kfilnd_tunables->lnd_traffic_class_str[0],
		       traffic_class);

	kfilnd_tunables->lnd_traffic_class =
		kfilnd_tcstr2num(kfilnd_tunables->lnd_traffic_class_str);

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

	if (kfilnd_tunables->lnd_traffic_class == -1) {
		CERROR("Invalid traffic_class \"%s\" - Valid values are: best_effort, low_latency, dedicated_access, bulk_data, scavenger, and network_ctrl\n",
		       kfilnd_tunables->lnd_traffic_class_str);
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

	if (wq_max_active > WQ_MAX_ACTIVE)
		wq_max_active = WQ_MAX_ACTIVE;

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

	if (kfilnd_tcstr2num(traffic_class) == -1) {
		CERROR("Invalid traffic_class \"%s\" - Valid values are: best_effort, low_latency, dedicated_access, bulk_data, scavenger, and network_ctrl\n",
		       traffic_class);
		return -EINVAL;
	}

	return 0;
}
