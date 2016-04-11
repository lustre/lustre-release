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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/o2iblnd/o2iblnd_modparams.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "o2iblnd.h"

static int service = 987;
module_param(service, int, 0444);
MODULE_PARM_DESC(service, "service number (within RDMA_PS_TCP)");

static int cksum = 0;
module_param(cksum, int, 0644);
MODULE_PARM_DESC(cksum, "set non-zero to enable message (not RDMA) checksums");

static int timeout = 50;
module_param(timeout, int, 0644);
MODULE_PARM_DESC(timeout, "timeout (seconds)");

/* Number of threads in each scheduler pool which is percpt,
 * we will estimate reasonable value based on CPUs if it's set to zero. */
static int nscheds;
module_param(nscheds, int, 0444);
MODULE_PARM_DESC(nscheds, "number of threads in each scheduler pool");

/* NB: this value is shared by all CPTs, it can grow at runtime */
static int ntx = 512;
module_param(ntx, int, 0444);
MODULE_PARM_DESC(ntx, "# of message descriptors allocated for each pool");

/* NB: this value is shared by all CPTs */
static int credits = 256;
module_param(credits, int, 0444);
MODULE_PARM_DESC(credits, "# concurrent sends");

static int peer_credits = 8;
module_param(peer_credits, int, 0444);
MODULE_PARM_DESC(peer_credits, "# concurrent sends to 1 peer");

static int peer_credits_hiw = 0;
module_param(peer_credits_hiw, int, 0444);
MODULE_PARM_DESC(peer_credits_hiw, "when eagerly to return credits");

static int peer_buffer_credits = 0;
module_param(peer_buffer_credits, int, 0444);
MODULE_PARM_DESC(peer_buffer_credits, "# per-peer router buffer credits");

static int peer_timeout = 180;
module_param(peer_timeout, int, 0444);
MODULE_PARM_DESC(peer_timeout, "Seconds without aliveness news to declare peer dead (<=0 to disable)");

static char *ipif_name = "ib0";
module_param(ipif_name, charp, 0444);
MODULE_PARM_DESC(ipif_name, "IPoIB interface name");

static int retry_count = 5;
module_param(retry_count, int, 0644);
MODULE_PARM_DESC(retry_count, "Retransmissions when no ACK received");

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

static int map_on_demand;
module_param(map_on_demand, int, 0444);
MODULE_PARM_DESC(map_on_demand, "map on demand");

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

kib_tunables_t kiblnd_tunables = {
        .kib_dev_failover           = &dev_failover,
        .kib_service                = &service,
        .kib_cksum                  = &cksum,
        .kib_timeout                = &timeout,
        .kib_keepalive              = &keepalive,
        .kib_ntx                    = &ntx,
        .kib_default_ipif           = &ipif_name,
        .kib_retry_count            = &retry_count,
        .kib_rnr_retry_count        = &rnr_retry_count,
        .kib_ib_mtu                 = &ib_mtu,
        .kib_require_priv_port      = &require_privileged_port,
	.kib_use_priv_port	    = &use_privileged_port,
	.kib_nscheds		    = &nscheds
};

static struct lnet_ioctl_config_o2iblnd_tunables default_tunables;

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

static char ipif_basename_space[32];

static struct ctl_table kiblnd_ctl_table[] = {
	{
		INIT_CTL_NAME
		.procname	= "service",
		.data		= &service,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "cksum",
		.data		= &cksum,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "timeout",
		.data		= &timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "ntx",
		.data		= &ntx,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "credits",
		.data		= &credits,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "peer_credits",
		.data		= &peer_credits,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "peer_credits_hiw",
		.data		= &peer_credits_hiw,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "peer_buffer_credits",
		.data		= &peer_buffer_credits,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "peer_timeout",
		.data		= &peer_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "ipif_name",
		.data		= ipif_basename_space,
		.maxlen		= sizeof(ipif_basename_space),
		.mode		= 0444,
		.proc_handler	= &proc_dostring
	},
	{
		INIT_CTL_NAME
		.procname	= "retry_count",
		.data		= &retry_count,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "rnr_retry_count",
		.data		= &rnr_retry_count,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "keepalive",
		.data		= &keepalive,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "concurrent_sends",
		.data		= &concurrent_sends,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "ib_mtu",
		.data		= &ib_mtu,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "map_on_demand",
		.data		= &map_on_demand,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "fmr_pool_size",
		.data		= &fmr_pool_size,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "fmr_flush_trigger",
		.data		= &fmr_flush_trigger,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "fmr_cache",
		.data		= &fmr_cache,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname	= "dev_failover",
		.data		= &dev_failover,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= &proc_dointvec
	},
	{ 0 }
};

static struct ctl_table kiblnd_top_ctl_table[] = {
	{
		INIT_CTL_NAME
		.procname	= "o2iblnd",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0555,
		.child		= kiblnd_ctl_table
	},
	{ 0 }
};

void
kiblnd_initstrtunable(char *space, char *str, int size)
{
        strncpy(space, str, size);
        space[size-1] = 0;
}

static void
kiblnd_sysctl_init (void)
{
	kiblnd_initstrtunable(ipif_basename_space, ipif_name,
			      sizeof(ipif_basename_space));

	kiblnd_tunables.kib_sysctl =
		register_sysctl_table(kiblnd_top_ctl_table);

	if (kiblnd_tunables.kib_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");
}

static void
kiblnd_sysctl_fini (void)
{
	if (kiblnd_tunables.kib_sysctl != NULL)
		unregister_sysctl_table(kiblnd_tunables.kib_sysctl);
}

#else

static void
kiblnd_sysctl_init (void)
{
}

static void
kiblnd_sysctl_fini (void)
{
}
#endif

/* # messages/RDMAs in-flight */
int
kiblnd_msg_queue_size(int version, lnet_ni_t *ni)
{
	if (version == IBLND_MSG_VERSION_1)
		return IBLND_MSG_QUEUE_SIZE_V1;
	else if (ni)
		return ni->ni_peertxcredits;
	else
		return peer_credits;
}

int
kiblnd_tunables_setup(lnet_ni_t *ni)
{
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;

	/*
	 * if there was no tunables specified, setup the tunables to be
	 * defaulted
	 */
	if (!ni->ni_lnd_tunables) {
		LIBCFS_ALLOC(ni->ni_lnd_tunables,
			     sizeof(*ni->ni_lnd_tunables));
		if (!ni->ni_lnd_tunables)
			return -ENOMEM;

		memcpy(&ni->ni_lnd_tunables->lt_tun_u.lt_o2ib,
		       &default_tunables, sizeof(*tunables));
	}
	tunables = &ni->ni_lnd_tunables->lt_tun_u.lt_o2ib;

	/* Current API version */
	tunables->lnd_version = 0;

	if (kiblnd_translate_mtu(*kiblnd_tunables.kib_ib_mtu) < 0) {
		CERROR("Invalid ib_mtu %d, expected 256/512/1024/2048/4096\n",
		       *kiblnd_tunables.kib_ib_mtu);
		return -EINVAL;
	}

	if (!ni->ni_peertimeout)
		ni->ni_peertimeout = peer_timeout;

	if (!ni->ni_maxtxcredits)
		ni->ni_maxtxcredits = credits;

	if (!ni->ni_peertxcredits)
		ni->ni_peertxcredits = peer_credits;

	if (!ni->ni_peerrtrcredits)
		ni->ni_peerrtrcredits = peer_buffer_credits;

	if (ni->ni_peertxcredits < IBLND_CREDITS_DEFAULT)
		ni->ni_peertxcredits = IBLND_CREDITS_DEFAULT;

	if (ni->ni_peertxcredits > IBLND_CREDITS_MAX)
		ni->ni_peertxcredits = IBLND_CREDITS_MAX;

	if (ni->ni_peertxcredits > credits)
		ni->ni_peertxcredits = credits;

	if (!tunables->lnd_peercredits_hiw)
		tunables->lnd_peercredits_hiw = peer_credits_hiw;

	if (tunables->lnd_peercredits_hiw < ni->ni_peertxcredits / 2)
		tunables->lnd_peercredits_hiw = ni->ni_peertxcredits / 2;

	if (tunables->lnd_peercredits_hiw >= ni->ni_peertxcredits)
		tunables->lnd_peercredits_hiw = ni->ni_peertxcredits - 1;

	if (tunables->lnd_map_on_demand < 0 ||
	    tunables->lnd_map_on_demand > IBLND_MAX_RDMA_FRAGS) {
		/* disable map-on-demand */
		tunables->lnd_map_on_demand = 0;
	}

	if (tunables->lnd_map_on_demand == 1) {
		/* don't make sense to create map if only one fragment */
		tunables->lnd_map_on_demand = 2;
	}

	if (tunables->lnd_concurrent_sends == 0) {
		if (tunables->lnd_map_on_demand > 0 &&
		    tunables->lnd_map_on_demand <= IBLND_MAX_RDMA_FRAGS / 8) {
			tunables->lnd_concurrent_sends =
						ni->ni_peertxcredits * 2;
		} else {
			tunables->lnd_concurrent_sends = ni->ni_peertxcredits;
		}
	}

	if (tunables->lnd_concurrent_sends > ni->ni_peertxcredits * 2)
		tunables->lnd_concurrent_sends = ni->ni_peertxcredits * 2;

	if (tunables->lnd_concurrent_sends < ni->ni_peertxcredits / 2)
		tunables->lnd_concurrent_sends = ni->ni_peertxcredits / 2;

	if (tunables->lnd_concurrent_sends < ni->ni_peertxcredits) {
		CWARN("Concurrent sends %d is lower than message "
		      "queue size: %d, performance may drop slightly.\n",
		      tunables->lnd_concurrent_sends, ni->ni_peertxcredits);
	}

	if (!tunables->lnd_fmr_pool_size)
		tunables->lnd_fmr_pool_size = fmr_pool_size;
	if (!tunables->lnd_fmr_flush_trigger)
		tunables->lnd_fmr_flush_trigger = fmr_flush_trigger;
	if (!tunables->lnd_fmr_cache)
		tunables->lnd_fmr_cache = fmr_cache;

	return 0;
}

int
kiblnd_tunables_init(void)
{
	default_tunables.lnd_version = 0;
	default_tunables.lnd_peercredits_hiw = peer_credits_hiw,
	default_tunables.lnd_map_on_demand = map_on_demand;
	default_tunables.lnd_concurrent_sends = concurrent_sends;
	default_tunables.lnd_fmr_pool_size = fmr_pool_size;
	default_tunables.lnd_fmr_flush_trigger = fmr_flush_trigger;
	default_tunables.lnd_fmr_cache = fmr_cache;

	kiblnd_sysctl_init();
	return 0;
}

void
kiblnd_tunables_fini(void)
{
	kiblnd_sysctl_fini();
}
