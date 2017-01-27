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
 * Copyright (c) 2014, 2016, Intel Corporation.
 *
 * Author:
 *   Amir Shehata <amir.shehata@intel.com>
 */

#ifndef LIB_LNET_CONFIG_API_H
#define LIB_LNET_CONFIG_API_H

#include <lnet/lnet.h>

#define LUSTRE_CFG_RC_NO_ERR			 0
#define LUSTRE_CFG_RC_BAD_PARAM			-1
#define LUSTRE_CFG_RC_MISSING_PARAM		-2
#define LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM	-3
#define LUSTRE_CFG_RC_OUT_OF_MEM		-4
#define LUSTRE_CFG_RC_GENERIC_ERR		-5
#define LUSTRE_CFG_RC_NO_MATCH			-6
#define LUSTRE_CFG_RC_MATCH			-7

#include <lnet/lnet.h>
#include <libcfs/util/string.h>

struct lnet_dlc_network_descr {
	struct list_head network_on_rule;
	__u32 nw_id;
	struct list_head nw_intflist;
};

struct lnet_dlc_intf_descr {
	struct list_head intf_on_network;
	char intf_name[LNET_MAX_STR_LEN];
	struct cfs_expr_list *cpt_expr;
};

/* forward declaration of the cYAML structure. */
struct cYAML;

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
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_config_route(char *nw, char *gw, int hops, int prio,
			     int seq_no, struct cYAML **err_rc);

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
 */
int lustre_lnet_show_route(char *nw, char *gw,
			   int hops, int prio, int detail,
			   int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc);

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
 */
int lustre_lnet_show_net(char *nw, int detail, int seq_no,
			 struct cYAML **show_rc, struct cYAML **err_rc);

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
 */
int lustre_lnet_show_routing(int seq_no, struct cYAML **show_rc,
			     struct cYAML **err_rc);

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
 *     seq_no - sequence number of the command
 *     err_rc - YAML strucutre of the resultant return code.
 */
int lustre_lnet_config_peer_nid(char *pnid, char **nid, int num_nids,
				bool mr, int seq_no, struct cYAML **err_rc);

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
 *     seq_no - sequence number of the command
 *     err_rc - YAML strucutre of the resultant return code.
 */
int lustre_lnet_del_peer_nid(char *pnid, char **nid, int num_nids,
			     int seq_no, struct cYAML **err_rc);

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
 *
 */
int lustre_lnet_show_peer(char *knid, int detail, int seq_no,
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
