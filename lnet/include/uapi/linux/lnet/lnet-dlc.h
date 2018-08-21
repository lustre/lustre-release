/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 *
 * LGPL HEADER END
 *
 */
/*
 * Copyright (c) 2014, 2017, Intel Corporation.
 */
/*
 * Author: Amir Shehata <amir.shehata@intel.com>
 */

#ifndef __UAPI_LNET_DLC_H_
#define __UAPI_LNET_DLC_H_

#include <linux/types.h>
/*
 * This is due to us being out of kernel and the way the OpenSFS branch
 * handles CFLAGS.
 */
#ifdef __KERNEL__
# include <uapi/linux/lnet/libcfs_ioctl.h>
# include <uapi/linux/lnet/lnet-types.h>
#else
# include <linux/lnet/libcfs_ioctl.h>
# include <linux/lnet/lnet-types.h>
#endif

#define MAX_NUM_SHOW_ENTRIES	32
#define LNET_MAX_STR_LEN	128
#define LNET_MAX_SHOW_NUM_CPT	128
#define LNET_MAX_SHOW_NUM_NID	128
#define LNET_UNDEFINED_HOPS	((__u32) -1)

/*
 * To allow for future enhancements to extend the tunables
 * add a hdr to this structure, so that the version can be set
 * and checked for backwards compatibility. Newer versions of LNet
 * can still work with older versions of lnetctl. The restriction is
 * that the structure can be added to and not removed from in order
 * to not invalidate older lnetctl utilities. Moreover, the order of
 * fields must remain the same, and new fields appended to the structure
 *
 * That said all existing LND tunables will be added in this structure
 * to avoid future changes.
 */
struct lnet_ioctl_config_lnd_cmn_tunables {
	__u32 lct_version;
	__s32 lct_peer_timeout;
	__s32 lct_peer_tx_credits;
	__s32 lct_peer_rtr_credits;
	__s32 lct_max_tx_credits;
};

struct lnet_ioctl_config_o2iblnd_tunables {
	__u32 lnd_version;
	__u32 lnd_peercredits_hiw;
	__u32 lnd_map_on_demand;
	__u32 lnd_concurrent_sends;
	__u32 lnd_fmr_pool_size;
	__u32 lnd_fmr_flush_trigger;
	__u32 lnd_fmr_cache;
	__u16 lnd_conns_per_peer;
	__u16 lnd_ntx;
};

struct lnet_lnd_tunables {
	union {
		struct lnet_ioctl_config_o2iblnd_tunables lnd_o2ib;
	} lnd_tun_u;
};

struct lnet_ioctl_config_lnd_tunables {
	struct lnet_ioctl_config_lnd_cmn_tunables lt_cmn;
	struct lnet_lnd_tunables lt_tun;
};

struct lnet_ioctl_net_config {
	char ni_interfaces[LNET_INTERFACES_NUM][LNET_MAX_STR_LEN];
	__u32 ni_status;
	__u32 ni_cpts[LNET_MAX_SHOW_NUM_CPT];
	char cfg_bulk[0];
};

#define LNET_TINY_BUF_IDX	0
#define LNET_SMALL_BUF_IDX	1
#define LNET_LARGE_BUF_IDX	2

/* # different router buffer pools */
#define LNET_NRBPOOLS		(LNET_LARGE_BUF_IDX + 1)

struct lnet_ioctl_pool_cfg {
	struct {
		__u32 pl_npages;
		__u32 pl_nbuffers;
		__u32 pl_credits;
		__u32 pl_mincredits;
	} pl_pools[LNET_NRBPOOLS];
	__u32 pl_routing;
};

struct lnet_ioctl_ping_data {
	struct libcfs_ioctl_hdr ping_hdr;

	__u32 op_param;
	__u32 ping_count;
	__u32 ping_flags;
	bool mr_info;
	struct lnet_process_id ping_id;
	struct lnet_process_id __user *ping_buf;
};

struct lnet_ioctl_config_data {
	struct libcfs_ioctl_hdr cfg_hdr;

	__u32 cfg_net;
	__u32 cfg_count;
	__u64 cfg_nid;
	__u32 cfg_ncpts;

	union {
		struct {
			__u32 rtr_hop;
			__u32 rtr_priority;
			__u32 rtr_flags;
		} cfg_route;
		struct {
			char net_intf[LNET_MAX_STR_LEN];
			__s32 net_peer_timeout;
			__s32 net_peer_tx_credits;
			__s32 net_peer_rtr_credits;
			__s32 net_max_tx_credits;
			__u32 net_cksum_algo;
			__u32 net_interface_count;
		} cfg_net;
		struct {
			__u32 buf_enable;
			__s32 buf_tiny;
			__s32 buf_small;
			__s32 buf_large;
		} cfg_buffers;
	} cfg_config_u;

	char cfg_bulk[0];
};

struct lnet_ioctl_comm_count {
	__u32 ico_get_count;
	__u32 ico_put_count;
	__u32 ico_reply_count;
	__u32 ico_ack_count;
	__u32 ico_hello_count;
};

struct lnet_ioctl_element_stats {
	__u32 iel_send_count;
	__u32 iel_recv_count;
	__u32 iel_drop_count;
};

enum lnet_health_type {
	LNET_HEALTH_TYPE_LOCAL_NI = 0,
	LNET_HEALTH_TYPE_PEER_NI,
};

struct lnet_ioctl_local_ni_hstats {
	struct libcfs_ioctl_hdr hlni_hdr;
	lnet_nid_t hlni_nid;
	__u32 hlni_local_interrupt;
	__u32 hlni_local_dropped;
	__u32 hlni_local_aborted;
	__u32 hlni_local_no_route;
	__u32 hlni_local_timeout;
	__u32 hlni_local_error;
	__s32 hlni_health_value;
};

struct lnet_ioctl_peer_ni_hstats {
	__u32 hlpni_remote_dropped;
	__u32 hlpni_remote_timeout;
	__u32 hlpni_remote_error;
	__u32 hlpni_network_timeout;
	__s32 hlpni_health_value;
};

struct lnet_ioctl_element_msg_stats {
	struct libcfs_ioctl_hdr im_hdr;
	__u32 im_idx;
	struct lnet_ioctl_comm_count im_send_stats;
	struct lnet_ioctl_comm_count im_recv_stats;
	struct lnet_ioctl_comm_count im_drop_stats;
};

/*
 * lnet_ioctl_config_ni
 *  This structure describes an NI configuration. There are multiple components
 *  when configuring an NI: Net, Interfaces, CPT list and LND tunables
 *  A network is passed as a string to the DLC and translated using
 *  libcfs_str2net()
 *  An interface is the name of the system configured interface
 *  (ex eth0, ib1)
 *  CPT is the list of CPTS LND tunables are passed in the lic_bulk area
 */
struct lnet_ioctl_config_ni {
	struct libcfs_ioctl_hdr lic_cfg_hdr;
	lnet_nid_t		lic_nid;
	char			lic_ni_intf[LNET_INTERFACES_NUM][LNET_MAX_STR_LEN];
	char			lic_legacy_ip2nets[LNET_MAX_STR_LEN];
	__u32			lic_cpts[LNET_MAX_SHOW_NUM_CPT];
	__u32			lic_ncpts;
	__u32			lic_status;
	__u32			lic_tcp_bonding;
	__u32			lic_idx;
	__s32			lic_dev_cpt;
	char			pad[4];
	char			lic_bulk[0];
};

struct lnet_peer_ni_credit_info {
	char cr_aliveness[LNET_MAX_STR_LEN];
	__u32 cr_refcount;
	__s32 cr_ni_peer_tx_credits;
	__s32 cr_peer_tx_credits;
	__s32 cr_peer_min_tx_credits;
	__u32 cr_peer_tx_qnob;
	__s32 cr_peer_rtr_credits;
	__s32 cr_peer_min_rtr_credits;
	__u32 cr_ncpt;
};

struct lnet_ioctl_peer {
	struct libcfs_ioctl_hdr pr_hdr;
	__u32 pr_count;
	__u32 pr_pad;
	lnet_nid_t pr_nid;

	union {
		struct lnet_peer_ni_credit_info  pr_peer_credits;
	} pr_lnd_u;
};

struct lnet_ioctl_peer_cfg {
	struct libcfs_ioctl_hdr prcfg_hdr;
	lnet_nid_t prcfg_prim_nid;
	lnet_nid_t prcfg_cfg_nid;
	__u32 prcfg_count;
	bool prcfg_mr;
	__u32 prcfg_state;
	__u32 prcfg_size;
	void __user *prcfg_bulk;
};

struct lnet_ioctl_reset_health_cfg {
	struct libcfs_ioctl_hdr rh_hdr;
	enum lnet_health_type rh_type;
	bool rh_all;
	int rh_value;
	lnet_nid_t rh_nid;
};

struct lnet_ioctl_recovery_list {
	struct libcfs_ioctl_hdr rlst_hdr;
	enum lnet_health_type rlst_type;
	int rlst_num_nids;
	lnet_nid_t rlst_nid_array[LNET_MAX_SHOW_NUM_NID];
};

struct lnet_ioctl_set_value {
	struct libcfs_ioctl_hdr sv_hdr;
	__u32 sv_value;
};

struct lnet_ioctl_lnet_stats {
	struct libcfs_ioctl_hdr st_hdr;
	struct lnet_counters st_cntrs;
};

#endif /* _LNET_DLC_H_ */
