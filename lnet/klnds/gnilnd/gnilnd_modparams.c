/*
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 *   Derived from work by: Eric Barton <eric@bartonsoftware.com>
 *   Author: Nic Henke <nic@cray.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "gnilnd.h"

static int credits = 256;
CFS_MODULE_PARM(credits, "i", int, 0444,
		"# concurrent sends");

static int eager_credits = 256 * 1024;
CFS_MODULE_PARM(eager_credits, "i", int, 0444,
		"# eager buffers");

static int peer_credits = 16;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
		"# LNet peer credits");

/* NB - we'll not actually limit sends to this, we just size the mailbox buffer
 * such that at most we'll have concurrent_sends * max_immediate messages
 * in the mailbox */
static int concurrent_sends = 0;
CFS_MODULE_PARM(concurrent_sends, "i", int, 0444,
		"# concurrent HW sends to 1 peer");

/* default for 2k nodes @ 16 peer credits */
static int fma_cq_size = 32768;
CFS_MODULE_PARM(fma_cq_size, "i", int, 0444,
		"size of the completion queue");

static int timeout = GNILND_BASE_TIMEOUT;
/* can't change @ runtime because LNet gets NI data at startup from
 * this value */
CFS_MODULE_PARM(timeout, "i", int, 0444,
		"communications timeout (seconds)");

/* time to wait between datagram timeout and sending of next dgram */
static int min_reconnect_interval = GNILND_MIN_RECONNECT_TO;
CFS_MODULE_PARM(min_reconnect_interval, "i", int, 0644,
		"minimum connection retry interval (seconds)");

/* if this goes longer than timeout, we'll timeout the TX before
 * the dgram */
static int max_reconnect_interval = GNILND_MAX_RECONNECT_TO;
CFS_MODULE_PARM(max_reconnect_interval, "i", int, 0644,
		"maximum connection retry interval (seconds)");

static int max_immediate = (2<<10);
CFS_MODULE_PARM(max_immediate, "i", int, 0644,
		"immediate/RDMA breakpoint");

static int checksum = GNILND_CHECKSUM_DEFAULT;
CFS_MODULE_PARM(checksum, "i", int, 0644,
		"0: None, 1: headers, 2: short msg, 3: all traffic");

static int checksum_dump = 0;
CFS_MODULE_PARM(checksum_dump, "i", int, 0644,
		"0: None, 1: dump log on failure, 2: payload data to D_INFO log");

static int bte_dlvr_mode = GNILND_RDMA_DLVR_OPTION;
CFS_MODULE_PARM(bte_dlvr_mode, "i", int, 0644,
		"enable hashing for BTE (RDMA) transfers");

static int bte_relaxed_ordering = 1;
CFS_MODULE_PARM(bte_relaxed_ordering, "i", int, 0644,
		"enable relaxed ordering (PASSPW) for BTE (RDMA) transfers");

#ifdef CONFIG_MK1OM
static int ptag = GNI_PTAG_LND_KNC;
#else
static int ptag = GNI_PTAG_LND;
#endif
CFS_MODULE_PARM(ptag, "i", int, 0444,
		"ptag for Gemini CDM");

static int max_retransmits = 1024;
CFS_MODULE_PARM(max_retransmits, "i", int, 0444,
		"max retransmits for FMA");

static int nwildcard = 4;
CFS_MODULE_PARM(nwildcard, "i", int, 0444,
		"# wildcard datagrams to post per net (interface)");

static int nice = -20;
CFS_MODULE_PARM(nice, "i", int, 0444,
		"nice value for kgnilnd threads, default -20");

static int rdmaq_intervals = 4;
CFS_MODULE_PARM(rdmaq_intervals, "i", int, 0644,
		"# intervals per second for rdmaq throttling, default 4, 0 to disable");

static int loops = 100;
CFS_MODULE_PARM(loops, "i", int, 0644,
		"# of loops before scheduler is friendly, default 100");

static int hash_size = 503;
CFS_MODULE_PARM(hash_size, "i", int, 0444,
		"prime number for peer/conn hash sizing, default 503");

static int peer_health = 0;
CFS_MODULE_PARM(peer_health, "i", int, 0444,
		"Disable peer timeout for LNet peer health, default off, > 0 to enable");

static int peer_timeout = -1;
CFS_MODULE_PARM(peer_timeout, "i", int, 0444,
		"Peer timeout used for peer_health, default based on gnilnd timeout, > -1 to manually set");

static int vmap_cksum = 0;
CFS_MODULE_PARM(vmap_cksum, "i", int, 0644,
		"use vmap for all kiov checksumming, default off");

static int mbox_per_block = GNILND_FMABLK;
CFS_MODULE_PARM(mbox_per_block, "i", int, 0644,
		"mailboxes per block");

static int nphys_mbox = 0;
CFS_MODULE_PARM(nphys_mbox, "i", int, 0444,
		"# mbox to preallocate from physical memory, default 0");

static int mbox_credits = GNILND_MBOX_CREDITS;
CFS_MODULE_PARM(mbox_credits, "i", int, 0644,
		"number of credits per mailbox");

static int sched_threads = GNILND_SCHED_THREADS;
CFS_MODULE_PARM(sched_threads, "i", int, 0444,
		"number of threads for moving data");

static int net_hash_size = 11;
CFS_MODULE_PARM(net_hash_size, "i", int, 0444,
		"prime number for net hash sizing, default 11");

static int hardware_timeout = GNILND_HARDWARE_TIMEOUT;
CFS_MODULE_PARM(hardware_timeout, "i", int, 0444,
		"maximum time for traffic to get from one node to another");

static int mdd_timeout = GNILND_MDD_TIMEOUT;
CFS_MODULE_PARM(mdd_timeout, "i", int, 0644,
		"maximum time (in minutes) for mdd to be held");

static int sched_timeout = GNILND_SCHED_TIMEOUT;
CFS_MODULE_PARM(sched_timeout, "i", int, 0644,
		"scheduler aliveness in seconds max time");

static int sched_nice = GNILND_SCHED_NICE;
CFS_MODULE_PARM(sched_nice, "i", int, 0444,
		"scheduler's nice setting, default compute 0 service -20");

static int reverse_rdma = GNILND_REVERSE_RDMA;
CFS_MODULE_PARM(reverse_rdma, "i", int, 0644,
		"Normal 0: Reverse GET: 1 Reverse Put: 2 Reverse Both: 3");

static int dgram_timeout = GNILND_DGRAM_TIMEOUT;
CFS_MODULE_PARM(dgram_timeout, "i", int, 0644,
		"dgram thread aliveness seconds max time");

static int efault_lbug = 0;
CFS_MODULE_PARM(efault_lbug, "i", int, 0644,
		"If a compute receives an EFAULT in"
		" a message should it LBUG. 0 off 1 on");

static int fast_reconn = GNILND_FAST_RECONNECT;
CFS_MODULE_PARM(fast_reconn, "i", int, 0644,
		"fast reconnect on connection timeout");

static int max_conn_purg = GNILND_PURGATORY_MAX;
CFS_MODULE_PARM(max_conn_purg, "i", int, 0644,
		"Max number of connections per peer in purgatory");

kgn_tunables_t kgnilnd_tunables = {
	.kgn_min_reconnect_interval = &min_reconnect_interval,
	.kgn_max_reconnect_interval = &max_reconnect_interval,
	.kgn_credits                = &credits,
	.kgn_peer_credits           = &peer_credits,
	.kgn_concurrent_sends       = &concurrent_sends,
	.kgn_fma_cq_size            = &fma_cq_size,
	.kgn_timeout                = &timeout,
	.kgn_max_immediate          = &max_immediate,
	.kgn_checksum               = &checksum,
	.kgn_checksum_dump          = &checksum_dump,
	.kgn_bte_dlvr_mode          = &bte_dlvr_mode,
	.kgn_bte_relaxed_ordering   = &bte_relaxed_ordering,
	.kgn_ptag                   = &ptag,
	.kgn_max_retransmits        = &max_retransmits,
	.kgn_nwildcard              = &nwildcard,
	.kgn_nice                   = &nice,
	.kgn_rdmaq_intervals        = &rdmaq_intervals,
	.kgn_loops                  = &loops,
	.kgn_peer_hash_size         = &hash_size,
	.kgn_peer_health            = &peer_health,
	.kgn_peer_timeout           = &peer_timeout,
	.kgn_vmap_cksum             = &vmap_cksum,
	.kgn_mbox_per_block         = &mbox_per_block,
	.kgn_nphys_mbox             = &nphys_mbox,
	.kgn_mbox_credits           = &mbox_credits,
	.kgn_sched_threads          = &sched_threads,
	.kgn_net_hash_size          = &net_hash_size,
	.kgn_hardware_timeout       = &hardware_timeout,
	.kgn_mdd_timeout            = &mdd_timeout,
	.kgn_sched_timeout	    = &sched_timeout,
	.kgn_sched_nice		    = &sched_nice,
	.kgn_reverse_rdma           = &reverse_rdma,
	.kgn_dgram_timeout          = &dgram_timeout,
	.kgn_eager_credits          = &eager_credits,
	.kgn_fast_reconn            = &fast_reconn,
	.kgn_efault_lbug            = &efault_lbug,
	.kgn_max_purgatory	    = &max_conn_purg
};

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
static struct ctl_table kgnilnd_ctl_table[] = {
	{
		INIT_CTL_NAME
		.procname = "min_reconnect_interval",
		.data     = &min_reconnect_interval,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "max_reconnect_interval",
		.data     = &max_reconnect_interval,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "credits",
		.data     = &credits,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "peer_credits",
		.data     = &peer_credits,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "fma_cq_size",
		.data     = &fma_cq_size,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "timeout",
		.data     = &timeout,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "max_immediate",
		.data     = &max_immediate,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "checksum",
		.data     = &checksum,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "bte_dlvr_mode",
		.data     = &bte_dlvr_mode,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "ptag",
		.data     = &ptag,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "nwildcard",
		.data     = &nwildcard,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "bte_relaxed_ordering",
		.data     = &bte_relaxed_ordering,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "checksum_dump",
		.data     = &checksum_dump,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "nice",
		.data     = &nice,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "rdmaq_intervals",
		.data     = &rdmaq_intervals,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "loops",
		.data     = &loops,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "hash_size",
		.data     = &hash_size,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "peer_health",
		.data     = &peer_health,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "vmap_cksum",
		.data     = &vmap_cksum,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "mbox_per_block",
		.data     = &mbox_per_block,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "mbox_credits"
		.data     = &mbox_credits,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "sched_threads"
		.data     = &sched_threads,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "net_hash_size",
		.data     = &net_hash_size,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "hardware_timeout",
		.data     = &hardware_timeout,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "mdd_timeout",
		.data     = &mdd_timeout,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "max_retransmits"
		.data     = &max_retransmits,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "concurrent_sends",
		.data     = &concurrent_sends,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "nphys_mbox",
		.data     = &nphys_mbox,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "sched_timeout",
		.data	  = &sched_timeout,
		.maxlen   = sizeof(int),
		.mode	  = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "sched_nice",
		.data	  = &sched_nice,
		.maxlen	  = sizeof(int),
		.mode	  = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "reverse_rdma",
		.data     = &reverse_rdma,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
		INIT_CTL_NAME
		.procname = "dgram_timeout"
		.data     = &dgram_timeout,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "peer_timeout"
		.data     = &peer_timeout,
		.maxlen   = sizeof(int),
		.mode     = 0444,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "eager_credits",
		.data	  = &eager_credits,
		.maxlen	  = sizeof(int),
		.mode	  = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "efault_lbug"
		.data     = &efault_lbug,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		INIT_CTL_NAME
		.procname = "max_conn_purg"
		.data	  = &max_conn_purg,
		.maxlen   = sizeof(int),
		.mode	  = 0644,
		.proc_handler = &proc_dointvec
	},
	{ 0 }
};

static struct ctl_table kgnilnd_top_ctl_table[] = {
	{
		INIT_CTL_NAME
		.procname = "gnilnd",
		.data     = NULL,
		.maxlen   = 0,
		.mode     = 0555,
		.child    = kgnilnd_ctl_table
	},
	{ 0 }
};
#endif

int
kgnilnd_tunables_init()
{
	int rc = 0;

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
	kgnilnd_tunables.kgn_sysctl =
		cfs_register_sysctl_table(kgnilnd_top_ctl_table, 0);

	if (kgnilnd_tunables.kgn_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");
#endif
	switch (*kgnilnd_tunables.kgn_checksum) {
	default:
		CERROR("Invalid checksum module parameter: %d\n",
		       *kgnilnd_tunables.kgn_checksum);
		rc = -EINVAL;
		GOTO(out, rc);
	case GNILND_CHECKSUM_OFF:
		/* no checksumming */
		break;
	case GNILND_CHECKSUM_SMSG_HEADER:
		LCONSOLE_INFO("SMSG header only checksumming enabled\n");
		break;
	case GNILND_CHECKSUM_SMSG:
		LCONSOLE_INFO("SMSG checksumming enabled\n");
		break;
	case GNILND_CHECKSUM_SMSG_BTE:
		LCONSOLE_INFO("SMSG + BTE checksumming enabled\n");
		break;
	}

	if (*kgnilnd_tunables.kgn_max_immediate > GNILND_MAX_IMMEDIATE) {
		LCONSOLE_ERROR("kgnilnd module parameter 'max_immediate' too large %d > %d\n",
		*kgnilnd_tunables.kgn_max_immediate, GNILND_MAX_IMMEDIATE);
		rc = -EINVAL;
		GOTO(out, rc);
	}

	if (*kgnilnd_tunables.kgn_mbox_per_block < 1) {
		*kgnilnd_tunables.kgn_mbox_per_block = 1;
	}

	if (*kgnilnd_tunables.kgn_concurrent_sends == 0) {
		*kgnilnd_tunables.kgn_concurrent_sends = *kgnilnd_tunables.kgn_peer_credits;
	} else if (*kgnilnd_tunables.kgn_concurrent_sends > *kgnilnd_tunables.kgn_peer_credits) {
		LCONSOLE_ERROR("kgnilnd parameter 'concurrent_sends' too large: %d > %d (peer_credits)\n",
			       *kgnilnd_tunables.kgn_concurrent_sends, *kgnilnd_tunables.kgn_peer_credits);
		rc = -EINVAL;
	}
out:
	return rc;
}

void
kgnilnd_tunables_fini()
{
#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
	if (kgnilnd_tunables.kgn_sysctl != NULL)
		cfs_unregister_sysctl_table(kgnilnd_tunables.kgn_sysctl);
#endif
}
