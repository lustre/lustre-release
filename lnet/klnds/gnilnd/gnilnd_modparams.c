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
module_param(credits, int, 0444);
MODULE_PARM_DESC(credits, "# concurrent sends");

static int eager_credits = 256 * 1024;
module_param(eager_credits, int, 0644);
MODULE_PARM_DESC(eager_credits, "# eager buffers");

static int peer_credits = 16;
module_param(peer_credits, int, 0444);
MODULE_PARM_DESC(peer_credits, "# LNet peer credits");

/* NB - we'll not actually limit sends to this, we just size the mailbox buffer
 * such that at most we'll have concurrent_sends * max_immediate messages
 * in the mailbox */
static int concurrent_sends = 0;
module_param(concurrent_sends, int, 0444);
MODULE_PARM_DESC(concurrent_sends, "# concurrent HW sends to 1 peer");

/* default for 2k nodes @ 16 peer credits */
static int fma_cq_size = 32768;
module_param(fma_cq_size, int, 0444);
MODULE_PARM_DESC(fma_cq_size, "size of the completion queue");

static int timeout = GNILND_BASE_TIMEOUT;
/* can't change @ runtime because LNet gets NI data at startup from
 * this value */
module_param(timeout, int, 0444);
MODULE_PARM_DESC(timeout, "communications timeout (seconds)");

/* time to wait between datagram timeout and sending of next dgram */
static int min_reconnect_interval = GNILND_MIN_RECONNECT_TO;
module_param(min_reconnect_interval, int, 0644);
MODULE_PARM_DESC(min_reconnect_interval, "minimum connection retry interval (seconds)");

/* if this goes longer than timeout, we'll timeout the TX before
 * the dgram */
static int max_reconnect_interval = GNILND_MAX_RECONNECT_TO;
module_param(max_reconnect_interval, int, 0644);
MODULE_PARM_DESC(max_reconnect_interval, "maximum connection retry interval (seconds)");

static int max_immediate = 2048;
module_param(max_immediate, int, 0444);
MODULE_PARM_DESC(max_immediate, "immediate/RDMA breakpoint");

static int checksum = GNILND_CHECKSUM_DEFAULT;
module_param(checksum, int, 0644);
MODULE_PARM_DESC(checksum, "0: None, 1: headers, 2: short msg, 3: all traffic");

static int checksum_dump = 0;
module_param(checksum_dump, int, 0644);
MODULE_PARM_DESC(checksum_dump, "0: None, 1: dump log on failure, 2: payload data to D_INFO log");

static int bte_put_dlvr_mode = GNILND_RDMA_DLVR_OPTION;
module_param(bte_put_dlvr_mode, int, 0644);
MODULE_PARM_DESC(bte_put_dlvr_mode, "Modify BTE Put Routing Option");

static int bte_get_dlvr_mode = GNILND_RDMA_DLVR_OPTION;
module_param(bte_get_dlvr_mode, int, 0644);
MODULE_PARM_DESC(bte_get_dlvr_mode, "Modify BTE Get Routing Option");

static int bte_relaxed_ordering = 1;
module_param(bte_relaxed_ordering, int, 0644);
MODULE_PARM_DESC(bte_relaxed_ordering, "enable relaxed ordering (PASSPW) for BTE (RDMA) transfers");

#ifdef CONFIG_MK1OM
static int ptag = GNI_PTAG_LND_KNC;
#else
static int ptag = GNI_PTAG_LND;
#endif
module_param(ptag, int, 0444);
MODULE_PARM_DESC(ptag, "ptag for Gemini CDM");

static int pkey = GNI_JOB_CREATE_COOKIE(GNI_PKEY_LND, 0);
module_param(pkey, int, 0444);
MODULE_PARM_DESC(pkey, "pkey for CDM");

static int max_retransmits = 128;
module_param(max_retransmits, int, 0444);
MODULE_PARM_DESC(max_retransmits,
		 "max retransmits for FMA before entering delay queue");

static int nwildcard = 4;
module_param(nwildcard, int, 0444);
MODULE_PARM_DESC(nwildcard, "# wildcard datagrams to post per net (interface)");

static int nice = -20;
module_param(nice, int, 0444);
MODULE_PARM_DESC(nice, "nice value for kgnilnd threads, default -20");

static int rdmaq_intervals = 4;
module_param(rdmaq_intervals, int, 0644);
MODULE_PARM_DESC(rdmaq_intervals, "# intervals per second for rdmaq throttling, default 4, 0 to disable");

static int loops = 100;
module_param(loops, int, 0644);
MODULE_PARM_DESC(loops, "# of loops before scheduler is friendly, default 100");

static int hash_size = 503;
module_param(hash_size, int, 0444);
MODULE_PARM_DESC(hash_size, "prime number for peer/conn hash sizing, default 503");

static int peer_health = 0;
module_param(peer_health, int, 0444);
MODULE_PARM_DESC(peer_health, "Disable peer timeout for LNet peer health, default off, > 0 to enable");

static int peer_timeout = -1;
module_param(peer_timeout, int, 0444);
MODULE_PARM_DESC(peer_timeout, "Peer timeout used for peer_health, default based on gnilnd timeout, > -1 to manually set");

static int vmap_cksum = 0;
module_param(vmap_cksum, int, 0644);
MODULE_PARM_DESC(vmap_cksum, "use vmap for all kiov checksumming, default off");

static int mbox_per_block = GNILND_FMABLK;
module_param(mbox_per_block, int, 0644);
MODULE_PARM_DESC(mbox_per_block, "mailboxes per block");

static int nphys_mbox = 0;
module_param(nphys_mbox, int, 0444);
MODULE_PARM_DESC(nphys_mbox, "# mbox to preallocate from physical memory, default 0");

static int mbox_credits = GNILND_MBOX_CREDITS;
module_param(mbox_credits, int, 0644);
MODULE_PARM_DESC(mbox_credits, "number of credits per mailbox");

static int sched_threads = GNILND_SCHED_THREADS;
module_param(sched_threads, int, 0444);
MODULE_PARM_DESC(sched_threads, "number of threads for moving data");

static int net_hash_size = 11;
module_param(net_hash_size, int, 0444);
MODULE_PARM_DESC(net_hash_size, "prime number for net hash sizing, default 11");

static int hardware_timeout = GNILND_HARDWARE_TIMEOUT;
module_param(hardware_timeout, int, 0444);
MODULE_PARM_DESC(hardware_timeout, "maximum time for traffic to get from one node to another");

static int mdd_timeout = GNILND_MDD_TIMEOUT;
module_param(mdd_timeout, int, 0644);
MODULE_PARM_DESC(mdd_timeout, "maximum time (in minutes) for mdd to be held");

static int sched_timeout = GNILND_SCHED_TIMEOUT;
module_param(sched_timeout, int, 0644);
MODULE_PARM_DESC(sched_timeout, "scheduler aliveness in seconds max time");

static int sched_nice = GNILND_SCHED_NICE;
module_param(sched_nice, int, 0444);
MODULE_PARM_DESC(sched_nice, "scheduler's nice setting, default compute 0 service -20");

static int reverse_rdma = GNILND_REVERSE_RDMA;
module_param(reverse_rdma, int, 0644);
MODULE_PARM_DESC(reverse_rdma, "Normal 0: Reverse GET: 1 Reverse Put: 2 Reverse Both: 3");

static int dgram_timeout = GNILND_DGRAM_TIMEOUT;
module_param(dgram_timeout, int, 0644);
MODULE_PARM_DESC(dgram_timeout, "dgram thread aliveness seconds max time");

static int efault_lbug = 0;
module_param(efault_lbug, int, 0644);
MODULE_PARM_DESC(efault_lbug, "If a compute receives an EFAULT in a message should it LBUG. 0 off 1 on");

static int fast_reconn = GNILND_FAST_RECONNECT;
module_param(fast_reconn, int, 0644);
MODULE_PARM_DESC(fast_reconn, "fast reconnect on connection timeout");

static int max_conn_purg = GNILND_PURGATORY_MAX;
module_param(max_conn_purg, int, 0644);
MODULE_PARM_DESC(max_conn_purg, "Max number of connections per peer in purgatory");

static int thread_affinity = 0;
module_param(thread_affinity, int, 0444);
MODULE_PARM_DESC(thread_affinity, "scheduler thread affinity default 0 (disabled)");

static int thread_safe = GNILND_TS_ENABLE;
module_param(thread_safe, int, 0444);
MODULE_PARM_DESC(thread_safe, "Use kgni thread safe API if available");

static int reg_fail_timeout = GNILND_REGFAILTO_DISABLE;
module_param(reg_fail_timeout, int, 0644);
MODULE_PARM_DESC(reg_fail_timeout, "fmablk registration timeout LBUG");

static int to_reconn_disable;
module_param(to_reconn_disable, int, 0644);
MODULE_PARM_DESC(to_reconn_disable,
		  "Timed out connection waits for peer before reconnecting");

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
	.kgn_bte_put_dlvr_mode      = &bte_put_dlvr_mode,
	.kgn_bte_get_dlvr_mode      = &bte_get_dlvr_mode,
	.kgn_bte_relaxed_ordering   = &bte_relaxed_ordering,
	.kgn_ptag                   = &ptag,
	.kgn_pkey                   = &pkey,
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
	.kgn_thread_affinity	    = &thread_affinity,
	.kgn_thread_safe	    = &thread_safe,
	.kgn_reg_fail_timeout	    = &reg_fail_timeout,
	.kgn_to_reconn_disable	    = &to_reconn_disable,
	.kgn_max_purgatory	    = &max_conn_purg
};

int
kgnilnd_tunables_init()
{
	int rc = 0;

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
