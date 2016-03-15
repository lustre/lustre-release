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
 * Copyright (c) 2014, Intel Corporation.
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

/* forward declaration of the cYAML structure. */
struct cYAML;

/*
 * lustre_lnet_config_lib_init()
 *   Initialize the Library to enable communication with the LNET kernel
 *   module.  Returns the device ID or -EINVAL if there is an error
 */
int lustre_lnet_config_lib_init();

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
 * lustre_lnet_config_net
 *   Send down an IOCTL to configure a network.
 *
 *   net - the network name
 *   intf - the interface of the network of the form net_name(intf)
 *   ip2net - this parameter allows configuring multiple networks.
 *	it takes precedence over the net and intf parameters
 *   peer_to - peer timeout
 *   peer_cr - peer credit
 *   peer_buf_cr - peer buffer credits
 *       - the above are LND tunable parameters and are optional
 *   credits - network interface credits
 *   smp - cpu affinity
 *   seq_no - sequence number of the request
 *   lnd_tunables - lnet specific tunable parameters
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_config_net(char *net, char *intf, char *ip2net,
			   int peer_to, int peer_cr, int peer_buf_cr,
			   int credits, char *smp, int seq_no,
			   struct lnet_ioctl_config_lnd_tunables *lnd_tunables,
			   struct cYAML **err_rc);

/*
 * lustre_lnet_del_net
 *   Send down an IOCTL to delete a network.
 *
 *   nw - network to delete.
 *   seq_no - sequence number of the request
 *   err_rc - [OUT] struct cYAML tree describing the error. Freed by caller
 */
int lustre_lnet_del_net(char *nw, int seq_no,
			struct cYAML **err_rc);

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
 * lustre_lnet_show_peer_credits
 *   Shows credit details on the peers in the system
 *
 *     seq_no - sequence number of the command
 *     show_rc - YAML structure of the resultant show
 *     err_rc - YAML strucutre of the resultant return code.
 */
int lustre_lnet_show_peer_credits(int seq_no, struct cYAML **show_rc,
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

#endif /* LIB_LNET_CONFIG_API_H */
