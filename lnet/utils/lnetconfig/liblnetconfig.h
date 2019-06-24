/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * LGPL HEADER END
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 *
 * Author:
 *   Amir Shehata <amir.shehata@intel.com>
 */

#ifndef LIB_LNET_CONFIG_API_H
#define LIB_LNET_CONFIG_API_H

#include <net/if.h>
#include <libcfs/util/string.h>
#include <linux/lnet/lnet-dlc.h>
#include <linux/lnet/nidstr.h>

#define LUSTRE_CFG_RC_NO_ERR			 0
#define LUSTRE_CFG_RC_BAD_PARAM			-1
#define LUSTRE_CFG_RC_MISSING_PARAM		-2
#define LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM	-3
#define LUSTRE_CFG_RC_OUT_OF_MEM		-4
#define LUSTRE_CFG_RC_GENERIC_ERR		-5
#define LUSTRE_CFG_RC_NO_MATCH			-6
#define LUSTRE_CFG_RC_MATCH			-7
#define LUSTRE_CFG_RC_SKIP			-8
#define LUSTRE_CFG_RC_LAST_ELEM			-9

enum lnetctl_cmd {
	LNETCTL_CONFIG_CMD	= 1,
	LNETCTL_UNCONFIG_CMD	= 2,
	LNETCTL_ADD_CMD		= 3,
	LNETCTL_DEL_CMD		= 4,
	LNETCTL_SHOW_CMD	= 5,
	LNETCTL_DBG_CMD		= 6,
	LNETCTL_MANAGE_CMD	= 7,
	LNETCTL_LAST_CMD
};

/*
 * Max number of nids we'll configure for a single peer via a single DLC
 * operation
 */
#define LNET_MAX_NIDS_PER_PEER 128

struct lnet_dlc_network_descr {
	struct list_head network_on_rule;
	__u32 nw_id;
	struct list_head nw_intflist;
};

struct lnet_dlc_intf_descr {
	struct list_head intf_on_network;
	char intf_name[IFNAMSIZ];
	struct cfs_expr_list *cpt_expr;
};

/* forward declaration of the cYAML structure. */
struct cYAML;

int tokenize_nidstr(char *nidstr, char *out[LNET_MAX_STR_LEN], char *err_str);

/*
 * lustre_lnet_config_lib_init()
 *   Initialize the Library to enable communication with the LNET kernel
 *   module.  Returns the device ID or -EINVAL if there is an error
 */
int lustre_lnet_config_lib_init();

/*
 * lustre_lnet_config_lib_uninit
 *	Uninitialize the DLC Library
 */
void lustre_lnet_config_lib_uninit();

/*
 * lustre_lnet_config_ni_system
 *   Initialize/Uninitialize the lnet NI system.
 *
 *   up - whehter to init or uninit the system
 *   load_ni_from_mod - load NI from mod params.
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *            caller
 */
int lustre_lnet_config_ni_system(bool up, bool load_ni_from_mod,
				 int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_config_route
 *   Send down an IOCTL to the kernel to configure the route
 *
 *   nw - network
 *   gw - gateway
 *   hops - number of hops passed down by the user
 *   prio - priority of the route
 *   sen - health sensitivity value for the gateway
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_config_route(char *nw, char *gw, int hops, int prio,
			     int sen, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_del_route
 *   Send down an IOCTL to the kernel to delete a route
 *
 *   nw - network
 *   gw - gateway
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_del_route(char *nw, char *gw, int seq_no,
			  struct cYAML **err_rc);

/*
 * lustre_lnet_show_route
 *   Send down an IOCTL to the kernel to show routes
 *   This function will get one route at a time and filter according to
 *   provided parameters. If no routes are available then it will dump all
 *   routes that are in the system.
 *
 *   nw - network.  Optional.  Used to filter output
 *   gw - gateway. Optional. Used to filter ouptut
 *   hops - number of hops passed down by the user
 *          Optional.  Used to filter output.
 *   prio - priority of the route.  Optional.  Used to filter output.
 *   detail - flag to indicate whether detail output is required
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] The show output in YAML.  Must be freed by caller.
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 *   backup - true to output only what's necessary for reconfiguring
 *	      a node.
 */
int lustre_lnet_show_route(char *nw, char *gw,
			   int hops, int prio, int detail,
			   int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc, bool backup);

/*
 * lustre_lnet_config_ni
 *   Send down an IOCTL to configure a network interface. It implicitly
 *   creates a network if one doesn't exist..
 *
 *   nw_descr - network and interface descriptor
 *   global_cpts - globally defined CPTs
 *   ip2net - this parameter allows configuring multiple networks.
 *	it takes precedence over the net and intf parameters
 *   tunables - LND tunables
 *   seq_no - sequence number of the request
 *   lnd_tunables - lnet specific tunable parameters
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_config_ni(struct lnet_dlc_network_descr *nw_descr,
			  struct cfs_expr_list *global_cpts,
			  char *ip2net,
			  struct lnet_ioctl_config_lnd_tunables *tunables,
			  int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_del_ni
 *   Send down an IOCTL to delete a network interface. It implicitly
 *   deletes a network if it becomes empty of nis
 *
 *   nw  - network and interface list
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_del_ni(struct lnet_dlc_network_descr *nw,
		       int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_net
 *   Send down an IOCTL to show networks.
 *   This function will use the nw paramter to filter the output.  If it's
 *   not provided then all networks are listed.
 *
 *   nw - network to show.  Optional.  Used to filter output.
 *   detail - flag to indicate if we require detail output.
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] The show output in YAML.  Must be freed by caller.
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 *   backup - true to output only what's necessary for reconfiguring
 *	      a node.
 */
int lustre_lnet_show_net(char *nw, int detail, int seq_no,
			 struct cYAML **show_rc, struct cYAML **err_rc,
			 bool backup);

/*
 * lustre_lnet_enable_routing
 *   Send down an IOCTL to enable or diable routing
 *
 *   enable - 1 to enable routing, 0 to disable routing
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_enable_routing(int enable, int seq_no,
			       struct cYAML **err_rc);

/*
 * lustre_lnet_config_numa_range
 *   Set the NUMA range which impacts the NIs to be selected
 *   during sending. If the NUMA range is large the NUMA
 *   distance between the message memory and the NI becomes
 *   less significant. The NUMA range is a relative number
 *   with no other meaning besides allowing a wider breadth
 *   for picking an NI to send from.
 *
 *   range - numa range value.
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_numa_range(int range, int seq_no,
				  struct cYAML **err_rc);

/*
 * lustre_lnet_show_num_range
 *   Get the currently set NUMA range
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing NUMA range info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_numa_range(int seq_no, struct cYAML **show_rc,
				struct cYAML **err_rc);

/*
 * lustre_lnet_config_ni_healthv
 *   set the health value of the NI. -1 resets the value to maximum.
 *
 *   value: health value to set.
 *   all: true to set all local NIs to that value.
 *   ni_nid: NI NID to set its health value. all parameter always takes
 *   precedence
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_ni_healthv(int value, bool all, char *ni_nid,
				  int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_config_peer_ni_healthv
 *   set the health value of the peer NI. -1 resets the value to maximum.
 *
 *   value: health value to set.
 *   all: true to set all local NIs to that value.
 *   pni_nid: Peer NI NID to set its health value. all parameter always takes
 *   precedence
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_peer_ni_healthv(int value, bool all, char *pni_nid,
				       int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_config_recov_intrv
 *   set the recovery interval in seconds. That's the interval to ping an
 *   unhealthy interface.
 *
 *   intrv - recovery interval value to configure
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_recov_intrv(int intrv, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_recov_intrv
 *    show the recovery interval set in the system
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing health sensitivity info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_recov_intrv(int seq_no, struct cYAML **show_rc,
				 struct cYAML **err_rc);

/*
 * lustre_lnet_config_rtr_sensitivity
 *   sets the router sensitivity percentage. If the percentage health
 *   of a router interface drops below that it's considered failed
 *
 *   sen - sensitivity value to configure
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_rtr_sensitivity(int sen, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_config_hsensitivity
 *   sets the health sensitivity; the value by which to decrement the
 *   health value of a local or peer NI. If 0 then health is turned off
 *
 *   sen - sensitivity value to configure
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_hsensitivity(int sen, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_hsensitivity
 *    show the health sensitivity in the system
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing health sensitivity info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_hsensitivity(int seq_no, struct cYAML **show_rc,
				  struct cYAML **err_rc);

/*
 * lustre_lnet_show_rtr_sensitivity
 *    show the router sensitivity percentage in the system
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing health sensitivity info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_rtr_sensitivity(int seq_no, struct cYAML **show_rc,
				     struct cYAML **err_rc);

/*
 * lustre_lnet_config_transaction_to
 *   sets the timeout after which a message expires or a timeout event is
 *   propagated for an expired response.
 *
 *   timeout - timeout value to configure
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_transaction_to(int timeout, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_transaction_to
 *    show the transaction timeout in the system
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing transaction timeout info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_transaction_to(int seq_no, struct cYAML **show_rc,
				    struct cYAML **err_rc);

/*
 * lustre_lnet_config_retry_count
 *   sets the maximum number of retries to resend a message
 *
 *   count - maximum value to configure
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_retry_count(int count, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_retry_count
 *    show current maximum number of retries in the system
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing retry count info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_retry_count(int seq_no, struct cYAML **show_rc,
				 struct cYAML **err_rc);

int lustre_lnet_show_local_ni_recovq(int seq_no, struct cYAML **show_rc,
				     struct cYAML **err_rc);

int lustre_lnet_show_peer_ni_recovq(int seq_no, struct cYAML **show_rc,
				    struct cYAML **err_rc);

/*
 * lustre_lnet_config_max_intf
 *   Sets the maximum number of interfaces per node. this tunable is
 *   primarily useful for sanity checks prior to allocating memory.
 *
 *   max - maximum value to configure
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_max_intf(int max, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_max_intf
 *    show current maximum interface setting
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing NUMA range info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_max_intf(int seq_no, struct cYAML **show_rc,
			      struct cYAML **err_rc);

/*
 * lustre_lnet_config_discovery
 *   Enable or disable peer discovery. Peer discovery is enabled by default.
 *
 *   enable - non-0 enables, 0 disables
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_discovery(int enable, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_discovery
 *    show current peer discovery setting
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing NUMA range info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_discovery(int seq_no, struct cYAML **show_rc,
			       struct cYAML **err_rc);

/*
 * lustre_lnet_config_drop_asym_route
 *   Drop or accept asymmetrical route messages. Accept by default.
 *
 *   drop - non-0 drops, 0 accepts
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_config_drop_asym_route(int drop, int seq_no,
				       struct cYAML **err_rc);

/*
 * lustre_lnet_show_drop_asym_route
 *    show current drop asym route setting
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] struct cYAML tree containing NUMA range info
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by
 *   caller
 */
int lustre_lnet_show_drop_asym_route(int seq_no, struct cYAML **show_rc,
				     struct cYAML **err_rc);

/*
 * lustre_lnet_config_buffers
 *   Send down an IOCTL to configure routing buffer sizes.  A value of 0 means
 *   default that particular buffer to default size. A value of -1 means
 *   leave the value of the buffer un changed.
 *
 *   tiny - tiny buffers
 *   small - small buffers
 *   large - large buffers.
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_config_buffers(int tiny, int small, int large,
			       int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_show_routing
 *   Send down an IOCTL to dump buffers and routing status
 *   This function is used to dump buffers for all CPU partitions.
 *
 *   seq_no - sequence number of the request
 *   show_rc - [OUT] The show output in YAML.  Must be freed by caller.
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 *   backup - true to output only what's necessary for reconfiguring
 *	      a node.
 */
int lustre_lnet_show_routing(int seq_no, struct cYAML **show_rc,
			     struct cYAML **err_rc, bool backup);

/*
 * lustre_lnet_show_stats
 *   Shows internal LNET statistics.  This is useful to display the
 *   current LNET activity, such as number of messages route, etc
 *
 *     seq_no - sequence number of the command
 *     show_rc - YAML structure of the resultant show
 *     err_rc - YAML strucutre of the resultant return code.
 */
int lustre_lnet_show_stats(int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc);

/*
 * lustre_lnet_config_peer_nid
 *   Add a peer nid to a peer with primary nid pnid. If no pnid is given
 *   then the first nid in the nid list becomes the primary nid for
 *   a newly created peer.
 *   Otherwise if pnid is provided and it's unique then a new peer is
 *   created with pnid as the primary NID and the nids in the nid list as
 *   secondary nids.
 *   If any of the peers nids provided in with exception to the pnid is
 *   not unique the operation fails. Some peer nids might have already
 *   been added. It's the role of the caller of this API to remove the
 *   added NIDs if they wish.
 *
 *     pnid - Primary NID of the peer
 *     nid - list of nids to add
 *     num_nids - number of nids in the nid array
 *     mr - true if this peer is MR capable.
 *     ip2nets - true if a list of nid expressions are given to configure
 *     multiple peers
 *     seq_no - sequence number of the command
 *     err_rc - YAML strucutre of the resultant return code.
 */
int lustre_lnet_config_peer_nid(char *pnid, char **nid, int num_nids,
				bool mr, bool ip2nets, int seq_no,
				struct cYAML **err_rc);

/*
 * lustre_lnet_config_peer_nidlist
 *  Add a peer NID to a peer with primary NID pnid. If a pnid is not provided
 *  then the first NID in the NID list becomes the primary NID for a newly
 *  created peer.
 *  Otherwise, if the provided primary NID is unique, then a new peer is
 *  created with this primary NID, and the NIDs in the NID list are added as
 *  secondary NIDs to this new peer.
 *  If any of the NIDs in the NID list are not unique then the operation
 *  fails. Some peer NIDs might have already been added. It's the responsibility
 *  of the caller of this API to remove the added NIDs if so desired.
 *
 *	pnid - The desired primary NID of a new peer, or the primary NID of
 *	       an existing peer.
 *	lnet_nidlist - List of LNet NIDs to add to the peer
 *	num_nids - The number of LNet NIDs in the lnet_nidlist array
 *	mr - Specifies whether this peer is MR capable.
 *	seq_no - sequence number of the command
 *	err_rc - YAML structure of the resultant return code
 */
int lustre_lnet_config_peer_nidlist(char *pnid, lnet_nid_t *lnet_nidlist,
				    int num_nids, bool mr, int seq_no,
				    struct cYAML **err_rc);

/*
 * lustre_lnet_del_peer_nid
 *  Delete the nids given in the nid list from the peer with primary NID
 *  pnid. If pnid is NULL or it doesn't identify a peer the operation
 *  fails and no change happens to the system.
 *  The operation is aborted on the first NID that fails to be deleted.
 *
 *     pnid - Primary NID of the peer
 *     nid - list of nids to add
 *     num_nids - number of nids in the nid array
 *     ip2nets - used to specify a range of nids
 *     seq_no - sequence number of the command
 *     err_rc - YAML strucutre of the resultant return code.
 */
int lustre_lnet_del_peer_nid(char *pnid, char **nid, int num_nids,
			     bool ip2nets, int seq_no, struct cYAML **err_rc);

/*
 * lustre_lnet_del_peer_nidlist
 *  Delete the NIDs given in the NID list from the peer with the primary NID
 *  pnid. If pnid is NULL, or it doesn't identify a peer, the operation fails,
 *  and no change happens to the system.
 *  The operation is aborted on the first NID that fails to be deleted.
 *
 *	pnid - The primary NID of the peer to be modified
 *	lnet_nidlist - The list of LNet NIDs to delete from the peer
 *	num_nids - the number of nids in the lnet_nidlist array
 *	seq_no - sequence number of the command
 *	err_rc - YAML structure of the resultant return code
 */
int lustre_lnet_del_peer_nidlist(char *pnid, lnet_nid_t *lnet_nidlist,
				 int num_nids, int seq_no,
				 struct cYAML **err_rc);
/*
 * lustre_lnet_show_peer
 *   Show the peer identified by nid, knid. If knid is NULL all
 *   peers in the system are shown.
 *
 *     knid - A NID of the peer
 *     detail - display detailed information
 *     seq_no - sequence number of the command
 *     show_rc - YAML structure of the resultant show
 *     err_rc - YAML strucutre of the resultant return code.
 *     backup - true to output only what's necessary for reconfiguring
 *		a node.
 *
 */
int lustre_lnet_show_peer(char *knid, int detail, int seq_no,
			  struct cYAML **show_rc, struct cYAML **err_rc,
			  bool backup);

/*
 * lustre_lnet_list_peer
 *   List the known peers.
 *
 *     seq_no - sequence number of the command
 *     show_rc - YAML structure of the resultant show
 *     err_rc - YAML strucutre of the resultant return code.
 *
 */
int lustre_lnet_list_peer(int seq_no,
			  struct cYAML **show_rc, struct cYAML **err_rc);

/* lustre_lnet_ping_nid
 *   Ping the nid list, pnids.
 *
 *    pnids - NID list to ping.
 *    timeout - timeout(seconds) for ping.
 *    seq_no - sequence number of the command.
 *    show_rc - YAML structure of the resultant show.
 *    err_rc - YAML strucutre of the resultant return code.
 *
 */
int lustre_lnet_ping_nid(char *pnid, int timeout, int seq_no,
			struct cYAML **show_rc, struct cYAML **err_rc);

/* lustre_lnet_discover_nid
 *   Discover the nid list, pnids.
 *
 *    pnids - NID list to discover.
 *    force - force discovery.
 *    seq_no - sequence number of the command.
 *    show_rc - YAML structure of the resultant show.
 *    err_rc - YAML strucutre of the resultant return code.
 *
 */
int lustre_lnet_discover_nid(char *pnid, int force, int seq_no,
			     struct cYAML **show_rc, struct cYAML **err_rc);

/*
 * lustre_yaml_config
 *   Parses the provided YAML file and then calls the specific APIs
 *   to configure the entities identified in the file
 *
 *   f - YAML file
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_yaml_config(char *f, struct cYAML **err_rc);

/*
 * lustre_yaml_del
 *   Parses the provided YAML file and then calls the specific APIs
 *   to delete the entities identified in the file
 *
 *   f - YAML file
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_yaml_del(char *f, struct cYAML **err_rc);

/*
 * lustre_yaml_show
 *   Parses the provided YAML file and then calls the specific APIs
 *   to show the entities identified in the file
 *
 *   f - YAML file
 *   show_rc - [OUT] The show output in YAML.  Must be freed by caller.
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_yaml_show(char *f, struct cYAML **show_rc,
		     struct cYAML **err_rc);

/*
 * lustre_yaml_exec
 *   Parses the provided YAML file and then calls the specific APIs
 *   to execute the entities identified in the file
 *
 *   f - YAML file
 *   show_rc - [OUT] The show output in YAML.  Must be freed by caller.
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_yaml_exec(char *f, struct cYAML **show_rc,
		     struct cYAML **err_rc);

/*
 * lustre_lnet_init_nw_descr
 *	initialize the network descriptor structure for use
 */
void lustre_lnet_init_nw_descr(struct lnet_dlc_network_descr *nw_descr);

/*
 * lustre_lnet_parse_interfaces
 *	prase an interface string and populate descriptor structures
 *		intf_str - interface string of the format
 *			<intf>[<expr>], <intf>[<expr>],..
 *		nw_descr - network descriptor to populate
 *		init - True to initialize nw_descr
 */
int lustre_lnet_parse_interfaces(char *intf_str,
				 struct lnet_dlc_network_descr *nw_descr);

/*
 * lustre_lnet_parse_nidstr
 *     This is a small wrapper around cfs_parse_nidlist.
 *         nidstr - A string parseable by cfs_parse_nidlist
 *         lnet_nidlist - An array of lnet_nid_t to hold the nids specified
 *                        by the nidstring.
 *         max_nids - Size of the lnet_nidlist array, and the maximum number of
 *                    nids that can be expressed by the nidstring. If the
 *                    nidstring expands to a larger number of nids than max_nids
 *                    then an error is returned.
 *         err_str - char pointer where we store an informative error
 *                   message when an error is encountered
 *     Returns:
 *         The number (> 0) of lnet_nid_t stored in the supplied array, or
 *         LUSTRE_CFG_RC_BAD_PARAM if:
 *           - nidstr is NULL
 *           - nidstr contains an asterisk. This character is not allowed
 *             because it would cause the size of the expanded nidlist to exceed
 *             the maximum number of nids that is supported by expected callers
 *             of this function.
 *           - cfs_parse_nidlist fails to parse the nidstring
 *           - The nidlist populated by cfs_parse_nidlist is empty
 *           - The nidstring expands to a larger number of nids than max_nids
 *           - The nidstring expands to zero nids
 *         LUSTRE_CFG_RC_OUT_OF_MEM if:
 *           - cfs_expand_nidlist can return ENOMEM. We return out of mem in
 *             this case.
 */
int lustre_lnet_parse_nidstr(char *nidstr, lnet_nid_t *lnet_nidlist,
			     int max_nids, char *err_str);

/*
 * lustre_lnet_parse_nids
 *	Parse a set of nids into a locally allocated array and return the
 *	pointer of the array to the caller. The caller is responsible for
 *	freeing the array. If an initial array is provided then copy over
 *	the contents of that array into the new array and append to it the
 *	new content.
 *	The nids can be of the form "nid [,nid, nid, nid]"
 *		nids: nids string to be parsed
 *		array: initial array of content
 *		size: num of elements in the array
 *		out_array: [OUT] new allocated array.
 *	Returns size of array
 *		sets the out_array to NULL on failure.
 */
int lustre_lnet_parse_nids(char *nids, char **array, int size,
			   char ***out_array);

#endif /* LIB_LNET_CONFIG_API_H */
