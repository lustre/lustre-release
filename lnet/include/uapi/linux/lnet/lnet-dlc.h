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
#include <linux/lnet/libcfs_ioctl.h>
#include <linux/lnet/lnet-types.h>

#define MAX_NUM_SHOW_ENTRIES	32
#define LNET_MAX_STR_LEN	128
#define LNET_MAX_SHOW_NUM_CPT	128
#define LNET_MAX_SHOW_NUM_NID	128
#define LNET_UNDEFINED_HOPS	((__u32) -1)

#define LNET_RT_ALIVE		(1 << 0)
#define LNET_RT_MULTI_HOP	(1 << 1)

/*
 * sparse kernel source annotations
 */
#ifndef __user
#define __user
#endif

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
	char ni_interface[LNET_MAX_STR_LEN];
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
	__u32 mr_info;
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
			__u32 rtr_sensitivity;
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
	char			lic_ni_intf[LNET_MAX_STR_LEN];
	char			lic_legacy_ip2nets[LNET_MAX_STR_LEN];
	__u32			lic_cpts[LNET_MAX_SHOW_NUM_CPT];
	__u32			lic_ncpts;
	__u32			lic_status;
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
	__u32 prcfg_mr;
	__u32 prcfg_state;
	__u32 prcfg_size;
	void __user *prcfg_bulk;
};

struct lnet_ioctl_reset_health_cfg {
	struct libcfs_ioctl_hdr rh_hdr;
	enum lnet_health_type rh_type:32;
	__u16 rh_all:1;
	__s16 rh_value;
	lnet_nid_t rh_nid;
};

struct lnet_ioctl_recovery_list {
	struct libcfs_ioctl_hdr rlst_hdr;
	enum lnet_health_type rlst_type:32;
	__u32 rlst_num_nids;
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

/* An IP, numeric NID or a Net number is composed of 1 or more of these
 * descriptor structures.
 */
struct lnet_range_expr {
	__u32 re_lo;
	__u32 re_hi;
	__u32 re_stride;
};

/* le_count identifies the number of lnet_range_expr in the bulk
 * which follows
 */
struct lnet_expressions {
	__u32 le_count;
};

/* A net descriptor has the net type, IE: O2IBLND, SOCKLND, etc and an
 * expression describing a net number range.
 */
struct lnet_ioctl_udsp_net_descr {
	__u32 ud_net_type;
	struct lnet_expressions ud_net_num_expr;
};

/* The UDSP descriptor header contains the type of matching criteria, SRC,
 * DST, RTE, etc and how many lnet_expressions compose the LNet portion of
 * the LNet NID. For example an IP can be
 * composed of 4 lnet_expressions , a gni can be composed of 1
 */
struct lnet_ioctl_udsp_descr_hdr {
	/* The literals SRC, DST and RTE are encoded
	 * here.
	 */
	__u32 ud_descr_type;
	__u32 ud_descr_count;
};

/* each matching expression in the UDSP is described with this.
 * The bulk format is as follows:
 *	1. 1x struct lnet_ioctl_udsp_net_descr
 *		-> the net part of the NID
 *	2. >=0 struct lnet_expressions
 *		-> the address part of the NID
 */
struct lnet_ioctl_udsp_descr {
	struct lnet_ioctl_udsp_descr_hdr iud_src_hdr;
	struct lnet_ioctl_udsp_net_descr iud_net;
};

/* The cumulative UDSP descriptor
 * The bulk format is as follows:
 *	1. >=1 struct lnet_ioctl_udsp_descr
 *
 * The size indicated in iou_hdr is the total size of the UDSP.
 *
 */
struct lnet_ioctl_udsp {
	struct libcfs_ioctl_hdr iou_hdr;
	__s32 iou_idx;
	__u32 iou_action_type;
	__u32 iou_bulk_size;
	union {
		__u32 priority;
	} iou_action;
	void __user *iou_bulk;
};

/* structure used to request udsp instantiation information on the
 * specified construct.
 *   cud_nid: the NID of the local or remote NI to pull info on.
 *   cud_nid_priority: NID prio of the requested NID.
 *   cud_net_priority: net prio of network of the requested NID.
 *   cud_pref_nid: array of preferred NIDs if it exists.
 */
struct lnet_ioctl_construct_udsp_info {
	struct libcfs_ioctl_hdr cud_hdr;
	__u32 cud_peer:1;
	lnet_nid_t cud_nid;
	__u32 cud_nid_priority;
	__u32 cud_net_priority;
	lnet_nid_t cud_pref_nid[LNET_MAX_SHOW_NUM_NID];
	lnet_nid_t cud_pref_rtr_nid[LNET_MAX_SHOW_NUM_NID];
};

#endif /* _LNET_DLC_H_ */
