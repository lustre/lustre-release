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
 * Copyright (c) 2014, 2015, Intel Corporation.
 *
 * Author:
 *   Amir Shehata <amir.shehata@intel.com>
 */

/*
 * There are two APIs:
 *  1. APIs that take the actual parameters expanded.  This is for other
 *  entities that would like to link against the library and call the APIs
 *  directly without having to form an intermediate representation.
 *  2. APIs that take a YAML file and parses out the information there and
 *  calls the APIs mentioned in 1
 */

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <libcfs/util/ioctl.h>
#include <lnet/lnetctl.h>
#include <lnet/socklnd.h>
#include "liblnd.h"
#include "liblnetconfig.h"
#include "cyaml.h"

#define CONFIG_CMD		"configure"
#define UNCONFIG_CMD		"unconfigure"
#define ADD_CMD			"add"
#define DEL_CMD			"del"
#define SHOW_CMD		"show"

int lustre_lnet_config_lib_init(void)
{
	return register_ioc_dev(LNET_DEV_ID, LNET_DEV_PATH,
				LNET_DEV_MAJOR, LNET_DEV_MINOR);
}

int lustre_lnet_config_ni_system(bool up, bool load_ni_from_mod,
				 int seq_no, struct cYAML **err_rc)
{
	struct libcfs_ioctl_data data;
	unsigned int opc;
	int rc;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"Success\"");

	LIBCFS_IOC_INIT(data);

	/* Reverse logic is used here in order not to change
	 * the lctl utility */
	data.ioc_flags = load_ni_from_mod ? 0 : 1;

	opc = up ? IOC_LIBCFS_CONFIGURE : IOC_LIBCFS_UNCONFIGURE;

	rc = l_ioctl(LNET_DEV_ID, opc, &data);
	if (rc != 0) {
		snprintf(err_str,
			sizeof(err_str),
			"\"LNet %s error: %s\"", (up) ? "configure" :
			"unconfigure", strerror(errno));
		rc = -errno;
	}

	cYAML_build_error(rc, seq_no, (up) ? CONFIG_CMD : UNCONFIG_CMD,
			  "lnet", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_route(char *nw, char *gw, int hops, int prio,
			     int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data data;
	lnet_nid_t gateway_nid;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	__u32 net = LNET_NIDNET(LNET_NID_ANY);
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"Success\"");

	if (nw == NULL || gw == NULL) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"missing mandatory parameter(s): '%s'\"",
			 (nw == NULL && gw == NULL) ? "network, gateway" :
			 (nw == NULL) ? "network" : "gateway");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	}

	net = libcfs_str2net(nw);
	if (net == LNET_NIDNET(LNET_NID_ANY)) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot parse net %s\"", nw);
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	if (LNET_NETTYP(net) == CIBLND    ||
	    LNET_NETTYP(net) == OPENIBLND ||
	    LNET_NETTYP(net) == IIBLND    ||
	    LNET_NETTYP(net) == VIBLND) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"obselete LNet type '%s'\"", libcfs_lnd2str(net));
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	gateway_nid = libcfs_str2nid(gw);
	if (gateway_nid == LNET_NID_ANY) {
		snprintf(err_str,
			sizeof(err_str),
			"\"cannot parse gateway NID '%s'\"", gw);
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	if (hops == -1) {
		/* hops is undefined */
		hops = LNET_UNDEFINED_HOPS;
	} else if (hops < 1 || hops > 255) {
		snprintf(err_str,
			sizeof(err_str),
			"\"invalid hop count %d, must be between 1 and 255\"",
			hops);
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	if (prio == -1) {
		prio = 0;
	} else if (prio < 0) {
		snprintf(err_str,
			 sizeof(err_str),
			"\"invalid priority %d, must be greater than 0\"",
			prio);
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	LIBCFS_IOC_INIT_V2(data, cfg_hdr);
	data.cfg_net = net;
	data.cfg_config_u.cfg_route.rtr_hop = hops;
	data.cfg_config_u.cfg_route.rtr_priority = prio;
	data.cfg_nid = gateway_nid;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_ROUTE, &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot add route: %s\"", strerror(errno));
		goto out;
	}

out:
	cYAML_build_error(rc, seq_no, ADD_CMD, "route", err_str, err_rc);

	return rc;
}

int lustre_lnet_del_route(char *nw, char *gw,
			  int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data data;
	lnet_nid_t gateway_nid;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	__u32 net = LNET_NIDNET(LNET_NID_ANY);
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"Success\"");

	if (nw == NULL || gw == NULL) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"missing mandatory parameter(s): '%s'\"",
			 (nw == NULL && gw == NULL) ? "network, gateway" :
			 (nw == NULL) ? "network" : "gateway");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	}

	net = libcfs_str2net(nw);
	if (net == LNET_NIDNET(LNET_NID_ANY)) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot parse net '%s'\"", nw);
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	if (LNET_NETTYP(net) == CIBLND    ||
	    LNET_NETTYP(net) == OPENIBLND ||
	    LNET_NETTYP(net) == IIBLND    ||
	    LNET_NETTYP(net) == VIBLND) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"obselete LNet type '%s'\"", libcfs_lnd2str(net));
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	gateway_nid = libcfs_str2nid(gw);
	if (gateway_nid == LNET_NID_ANY) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot parse gateway NID '%s'\"", gw);
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	LIBCFS_IOC_INIT_V2(data, cfg_hdr);
	data.cfg_net = net;
	data.cfg_nid = gateway_nid;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_ROUTE, &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot delete route: %s\"", strerror(errno));
		goto out;
	}

out:
	cYAML_build_error(rc, seq_no, DEL_CMD, "route", err_str, err_rc);

	return rc;
}

int lustre_lnet_show_route(char *nw, char *gw, int hops, int prio, int detail,
			   int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data data;
	lnet_nid_t gateway_nid;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	int l_errno = 0;
	__u32 net = LNET_NIDNET(LNET_NID_ANY);
	int i;
	struct cYAML *root = NULL, *route = NULL, *item = NULL;
	struct cYAML *first_seq = NULL;
	char err_str[LNET_MAX_STR_LEN];
	bool exist = false;

	snprintf(err_str, sizeof(err_str),
		 "\"out of memory\"");

	if (nw != NULL) {
		net = libcfs_str2net(nw);
		if (net == LNET_NIDNET(LNET_NID_ANY)) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\"cannot parse net '%s'\"", nw);
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			goto out;
		}

		if (LNET_NETTYP(net) == CIBLND    ||
		    LNET_NETTYP(net) == OPENIBLND ||
		    LNET_NETTYP(net) == IIBLND    ||
		    LNET_NETTYP(net) == VIBLND) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\"obsolete LNet type '%s'\"",
				 libcfs_lnd2str(net));
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			goto out;
		}
	} else {
		/* show all routes without filtering on net */
		net = LNET_NIDNET(LNET_NID_ANY);
	}

	if (gw != NULL) {
		gateway_nid = libcfs_str2nid(gw);
		if (gateway_nid == LNET_NID_ANY) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\"cannot parse gateway NID '%s'\"", gw);
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			goto out;
		}
	} else
		/* show all routes with out filtering on gateway */
		gateway_nid = LNET_NID_ANY;

	if ((hops < 1 && hops != -1) || hops > 255) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"invalid hop count %d, must be between 0 and 256\"",
			 hops);
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	/* create struct cYAML root object */
	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	route = cYAML_create_seq(root, "route");
	if (route == NULL)
		goto out;

	for (i = 0;; i++) {
		LIBCFS_IOC_INIT_V2(data, cfg_hdr);
		data.cfg_count = i;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_ROUTE, &data);
		if (rc != 0) {
			l_errno = errno;
			break;
		}

		/* filter on provided data */
		if (net != LNET_NIDNET(LNET_NID_ANY) &&
		    net != data.cfg_net)
			continue;

		if (gateway_nid != LNET_NID_ANY &&
		    gateway_nid != data.cfg_nid)
			continue;

		if (hops != -1 &&
		    hops != data.cfg_config_u.cfg_route.rtr_hop)
			continue;

		if (prio != -1 &&
		    prio != data.cfg_config_u.cfg_route.rtr_priority)
			continue;

		/* default rc to -1 incase we hit the goto */
		rc = -1;
		exist = true;

		item = cYAML_create_seq_item(route);
		if (item == NULL)
			goto out;

		if (first_seq == NULL)
			first_seq = item;

		if (cYAML_create_string(item, "net",
					libcfs_net2str(data.cfg_net)) == NULL)
			goto out;

		if (cYAML_create_string(item, "gateway",
					libcfs_nid2str(data.cfg_nid)) == NULL)
			goto out;

		if (detail) {
			if (cYAML_create_number(item, "hop",
						data.cfg_config_u.cfg_route.
							rtr_hop) ==
			    NULL)
				goto out;

			if (cYAML_create_number(item, "priority",
						data.cfg_config_u.
						cfg_route.rtr_priority) == NULL)
				goto out;

			if (cYAML_create_string(item, "state",
						data.cfg_config_u.cfg_route.
							rtr_flags ?
						"up" : "down") == NULL)
				goto out;
		}
	}

	/* print output iff show_rc is not provided */
	if (show_rc == NULL)
		cYAML_print_tree(root);

	if (l_errno != ENOENT) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get routes: %s\"",
			 strerror(l_errno));
		rc = -l_errno;
		goto out;
	} else
		rc = LUSTRE_CFG_RC_NO_ERR;

	snprintf(err_str, sizeof(err_str), "\"success\"");
out:
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR || !exist) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		struct cYAML *show_node;
		/* find the route node, if one doesn't exist then
		 * insert one.  Otherwise add to the one there
		 */
		show_node = cYAML_get_object_item(*show_rc, "route");
		if (show_node != NULL && cYAML_is_sequence(show_node)) {
			cYAML_insert_child(show_node, first_seq);
			free(route);
			free(root);
		} else if (show_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
						route);
			free(root);
		} else {
			cYAML_free_tree(root);
		}
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, "route", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_net(char *net, char *intf, char *ip2net,
			   int peer_to, int peer_cr, int peer_buf_cr,
			   int credits, char *smp, int seq_no,
			   struct lnet_ioctl_config_lnd_tunables *lnd_tunables,
			   struct cYAML **err_rc)
{
	struct lnet_ioctl_config_lnd_tunables *lnd = NULL;
	struct lnet_ioctl_config_data *data;
	size_t ioctl_size = sizeof(*data);
	char buf[LNET_MAX_STR_LEN];
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"success\"");

	/* No need to register lo */
	if (net != NULL && !strcmp(net, "lo"))
		return 0;

	if (ip2net == NULL && (intf == NULL || net == NULL)) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"mandatory parameter '%s' not specified."
			 " Optionally specify ip2net parameter\"",
			 (intf == NULL && net == NULL) ? "net, if" :
			 (intf == NULL) ? "if" : "net");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	}

	if (peer_to != -1 && peer_to <= 0) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"peer timeout %d, must be greater than 0\"",
			 peer_to);
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	if (ip2net != NULL && strlen(ip2net) >= sizeof(buf)) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"ip2net string too long %d\"",
				(int)strlen(ip2net));
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	if (lnd_tunables != NULL)
		ioctl_size += sizeof(*lnd_tunables);

	data = calloc(1, ioctl_size);
	if (data == NULL)
		goto out;

	if (ip2net == NULL)
		snprintf(buf, sizeof(buf) - 1, "%s(%s)%s",
			net, intf,
			(smp) ? smp : "");

	LIBCFS_IOC_INIT_V2(*data, cfg_hdr);
	strncpy(data->cfg_config_u.cfg_net.net_intf,
		(ip2net != NULL) ? ip2net : buf, sizeof(buf));
	data->cfg_config_u.cfg_net.net_peer_timeout = peer_to;
	data->cfg_config_u.cfg_net.net_peer_tx_credits = peer_cr;
	data->cfg_config_u.cfg_net.net_peer_rtr_credits = peer_buf_cr;
	data->cfg_config_u.cfg_net.net_max_tx_credits = credits;
	/* Add in tunable settings if available */
	if (lnd_tunables != NULL) {
		lnd = (struct lnet_ioctl_config_lnd_tunables *)data->cfg_bulk;

		data->cfg_hdr.ioc_len = ioctl_size;
		memcpy(lnd, lnd_tunables, sizeof(*lnd_tunables));
	}

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_NET, data);
	if (rc < 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot add network: %s\"", strerror(errno));
	}
	free(data);

out:
	cYAML_build_error(rc, seq_no, ADD_CMD, "net", err_str, err_rc);

	return rc;
}

int lustre_lnet_del_net(char *nw, int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data data;
	__u32 net = LNET_NIDNET(LNET_NID_ANY);
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"success\"");

	if (nw == NULL) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"missing mandatory parameter\"");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	}

	net = libcfs_str2net(nw);
	if (net == LNET_NIDNET(LNET_NID_ANY)) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot parse net '%s'\"", nw);
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	LIBCFS_IOC_INIT_V2(data, cfg_hdr);
	data.cfg_net = net;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_NET, &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot delete network: %s\"", strerror(errno));
		goto out;
	}

out:
	cYAML_build_error(rc, seq_no, DEL_CMD, "net", err_str, err_rc);

	return rc;
}

int lustre_lnet_show_net(char *nw, int detail, int seq_no,
			 struct cYAML **show_rc, struct cYAML **err_rc)
{
	char *buf;
	struct lnet_ioctl_config_lnd_tunables *lnd_cfg;
	struct lnet_ioctl_config_data *data;
	struct lnet_ioctl_net_config *net_config;
	__u32 net = LNET_NIDNET(LNET_NID_ANY);
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM, i, j;
	int l_errno = 0;
	struct cYAML *root = NULL, *tunables = NULL, *net_node = NULL,
		*interfaces = NULL, *item = NULL, *first_seq = NULL;
	int str_buf_len = LNET_MAX_SHOW_NUM_CPT * 2;
	char str_buf[str_buf_len];
	char *pos;
	char err_str[LNET_MAX_STR_LEN];
	bool exist = false;
	size_t buf_len;

	snprintf(err_str, sizeof(err_str), "\"out of memory\"");

	buf_len = sizeof(*data) + sizeof(*net_config) + sizeof(*lnd_cfg);
	buf = calloc(1, buf_len);
	if (buf == NULL)
		goto out;

	data = (struct lnet_ioctl_config_data *)buf;

	if (nw != NULL) {
		net = libcfs_str2net(nw);
		if (net == LNET_NIDNET(LNET_NID_ANY)) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\"cannot parse net '%s'\"", nw);
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			goto out;
		}
	}

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	net_node = cYAML_create_seq(root, "net");
	if (net_node == NULL)
		goto out;

	for (i = 0;; i++) {
		pos = str_buf;

		memset(buf, 0, buf_len);

		LIBCFS_IOC_INIT_V2(*data, cfg_hdr);
		/*
		 * set the ioc_len to the proper value since INIT assumes
		 * size of data
		 */
		data->cfg_hdr.ioc_len = buf_len;
		data->cfg_count = i;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_NET, data);
		if (rc != 0) {
			l_errno = errno;
			break;
		}

		/* filter on provided data */
		if (net != LNET_NIDNET(LNET_NID_ANY) &&
		    net != LNET_NIDNET(data->cfg_nid))
			continue;

		/* default rc to -1 in case we hit the goto */
		rc = -1;
		exist = true;

		net_config = (struct lnet_ioctl_net_config *)data->cfg_bulk;

		/* create the tree to be printed. */
		item = cYAML_create_seq_item(net_node);
		if (item == NULL)
			goto out;

		if (first_seq == NULL)
			first_seq = item;

		if (cYAML_create_string(item, "net",
					libcfs_net2str(
						LNET_NIDNET(data->cfg_nid)))
		    == NULL)
			goto out;

		if (cYAML_create_string(item, "nid",
					libcfs_nid2str(data->cfg_nid)) == NULL)
			goto out;

		if (cYAML_create_string(item, "status",
					(net_config->ni_status ==
					  LNET_NI_STATUS_UP) ?
					    "up" : "down") == NULL)
			goto out;

		/* don't add interfaces unless there is at least one
		 * interface */
		if (strlen(net_config->ni_interfaces[0]) > 0) {
			interfaces = cYAML_create_object(item, "interfaces");
			if (interfaces == NULL)
				goto out;

			for (j = 0; j < LNET_MAX_INTERFACES; j++) {
				if (lustre_interface_show_net(interfaces, j,
							      detail, data,
							      net_config) < 0)
					goto out;
			}
		}

		if (detail) {
			char *limit;

			tunables = cYAML_create_object(item, "tunables");
			if (tunables == NULL)
				goto out;

			if (cYAML_create_number(tunables, "peer_timeout",
						data->cfg_config_u.cfg_net.
						net_peer_timeout) == NULL)
				goto out;

			if (cYAML_create_number(tunables, "peer_credits",
						data->cfg_config_u.cfg_net.
						net_peer_tx_credits) == NULL)
				goto out;

			if (cYAML_create_number(tunables,
						"peer_buffer_credits",
						data->cfg_config_u.cfg_net.
						net_peer_rtr_credits) == NULL)
				goto out;

			if (cYAML_create_number(tunables, "credits",
						data->cfg_config_u.cfg_net.
						net_max_tx_credits) == NULL)
				goto out;

			/* out put the CPTs in the format: "[x,x,x,...]" */
			limit = str_buf + str_buf_len - 3;
			pos += snprintf(pos, limit - pos, "\"[");
			for (j = 0 ; data->cfg_ncpts > 1 &&
				j < data->cfg_ncpts &&
				pos < limit; j++) {
				pos += snprintf(pos, limit - pos,
						"%d", net_config->ni_cpts[j]);
				if ((j + 1) < data->cfg_ncpts)
					pos += snprintf(pos, limit - pos, ",");
			}
			pos += snprintf(pos, 3, "]\"");

			if (data->cfg_ncpts > 1 &&
			    cYAML_create_string(tunables, "CPT",
						str_buf) == NULL)
				goto out;
		}
	}

	/* Print out the net information only if show_rc is not provided */
	if (show_rc == NULL)
		cYAML_print_tree(root);

	if (l_errno != ENOENT) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get networks: %s\"",
			 strerror(l_errno));
		rc = -l_errno;
		goto out;
	} else
		rc = LUSTRE_CFG_RC_NO_ERR;

	snprintf(err_str, sizeof(err_str), "\"success\"");
out:
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR || !exist) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		struct cYAML *show_node;
		/* find the net node, if one doesn't exist
		 * then insert one.  Otherwise add to the one there
		 */
		show_node = cYAML_get_object_item(*show_rc, "net");
		if (show_node != NULL && cYAML_is_sequence(show_node)) {
			cYAML_insert_child(show_node, first_seq);
			free(net_node);
			free(root);
		} else if (show_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
						net_node);
			free(root);
		} else {
			cYAML_free_tree(root);
		}
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, "net", err_str, err_rc);

	return rc;
}

int lustre_lnet_enable_routing(int enable, int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data data;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"success\"");

	LIBCFS_IOC_INIT_V2(data, cfg_hdr);
	data.cfg_config_u.cfg_buffers.buf_enable = (enable) ? 1 : 0;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_CONFIG_RTR, &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot %s routing %s\"",
			 (enable) ? "enable" : "disable", strerror(errno));
		goto out;
	}

out:
	cYAML_build_error(rc, seq_no,
			 (enable) ? ADD_CMD : DEL_CMD,
			 "routing", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_buffers(int tiny, int small, int large, int seq_no,
			       struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data data;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"success\"");

	/* -1 indicates to ignore changes to this field */
	if (tiny < -1 || small < -1 || large < -1) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"tiny, small and large must be >= 0\"");
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	LIBCFS_IOC_INIT_V2(data, cfg_hdr);
	data.cfg_config_u.cfg_buffers.buf_tiny = tiny;
	data.cfg_config_u.cfg_buffers.buf_small = small;
	data.cfg_config_u.cfg_buffers.buf_large = large;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_BUF, &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot configure buffers: %s\"", strerror(errno));
		goto out;
	}

out:
	cYAML_build_error(rc, seq_no, ADD_CMD, "buf", err_str, err_rc);

	return rc;
}

int lustre_lnet_show_routing(int seq_no, struct cYAML **show_rc,
			     struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data *data;
	struct lnet_ioctl_pool_cfg *pool_cfg = NULL;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	int l_errno = 0;
	char *buf;
	char *pools[LNET_NRBPOOLS] = {"tiny", "small", "large"};
	int buf_count[LNET_NRBPOOLS] = {0};
	struct cYAML *root = NULL, *pools_node = NULL,
		     *type_node = NULL, *item = NULL, *cpt = NULL,
		     *first_seq = NULL, *buffers = NULL;
	int i, j;
	char err_str[LNET_MAX_STR_LEN];
	char node_name[LNET_MAX_STR_LEN];
	bool exist = false;

	snprintf(err_str, sizeof(err_str), "\"out of memory\"");

	buf = calloc(1, sizeof(*data) + sizeof(*pool_cfg));
	if (buf == NULL)
		goto out;

	data = (struct lnet_ioctl_config_data *)buf;

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	pools_node = cYAML_create_seq(root, "routing");
	if (pools_node == NULL)
		goto out;

	for (i = 0;; i++) {
		LIBCFS_IOC_INIT_V2(*data, cfg_hdr);
		data->cfg_hdr.ioc_len = sizeof(struct lnet_ioctl_config_data) +
					sizeof(struct lnet_ioctl_pool_cfg);
		data->cfg_count = i;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_BUF, data);
		if (rc != 0) {
			l_errno = errno;
			break;
		}

		exist = true;

		pool_cfg = (struct lnet_ioctl_pool_cfg *)data->cfg_bulk;

		snprintf(node_name, sizeof(node_name), "cpt[%d]", i);
		item = cYAML_create_seq_item(pools_node);
		if (item == NULL)
			goto out;

		if (first_seq == NULL)
			first_seq = item;

		cpt = cYAML_create_object(item, node_name);
		if (cpt == NULL)
			goto out;

		/* create the tree  and print */
		for (j = 0; j < LNET_NRBPOOLS; j++) {
			type_node = cYAML_create_object(cpt, pools[j]);
			if (type_node == NULL)
				goto out;
			if (cYAML_create_number(type_node, "npages",
						pool_cfg->pl_pools[j].pl_npages)
			    == NULL)
				goto out;
			if (cYAML_create_number(type_node, "nbuffers",
						pool_cfg->pl_pools[j].
						  pl_nbuffers) == NULL)
				goto out;
			if (cYAML_create_number(type_node, "credits",
						pool_cfg->pl_pools[j].
						   pl_credits) == NULL)
				goto out;
			if (cYAML_create_number(type_node, "mincredits",
						pool_cfg->pl_pools[j].
						   pl_mincredits) == NULL)
				goto out;
			/* keep track of the total count for each of the
			 * tiny, small and large buffers */
			buf_count[j] += pool_cfg->pl_pools[j].pl_nbuffers;
		}
	}

	if (pool_cfg != NULL) {
		item = cYAML_create_seq_item(pools_node);
		if (item == NULL)
			goto out;

		if (cYAML_create_number(item, "enable", pool_cfg->pl_routing) ==
		    NULL)
			goto out;
	}

	/* create a buffers entry in the show. This is necessary so that
	 * if the YAML output is used to configure a node, the buffer
	 * configuration takes hold */
	buffers = cYAML_create_object(root, "buffers");
	if (buffers == NULL)
		goto out;

	for (i = 0; i < LNET_NRBPOOLS; i++) {
		if (cYAML_create_number(buffers, pools[i], buf_count[i]) == NULL)
			goto out;
	}

	if (show_rc == NULL)
		cYAML_print_tree(root);

	if (l_errno != ENOENT) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get routing information: %s\"",
			 strerror(l_errno));
		rc = -l_errno;
		goto out;
	} else
		rc = LUSTRE_CFG_RC_NO_ERR;

	snprintf(err_str, sizeof(err_str), "\"success\"");
	rc = LUSTRE_CFG_RC_NO_ERR;

out:
	free(buf);
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR || !exist) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		struct cYAML *routing_node;
		/* there should exist only one routing block and one
		 * buffers block. If there already exists a previous one
		 * then don't add another */
		routing_node = cYAML_get_object_item(*show_rc, "routing");
		if (routing_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
						root->cy_child);
			free(root);
		} else {
			cYAML_free_tree(root);
		}
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, "routing", err_str, err_rc);

	return rc;
}

int lustre_lnet_show_peer_credits(int seq_no, struct cYAML **show_rc,
				  struct cYAML **err_rc)
{
	struct lnet_ioctl_peer peer_info;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM, ncpt = 0, i = 0, j = 0;
	int l_errno = 0;
	struct cYAML *root = NULL, *peer = NULL, *first_seq = NULL,
		     *peer_root = NULL;
	char err_str[LNET_MAX_STR_LEN];
	bool ncpt_set = false;

	snprintf(err_str, sizeof(err_str),
		 "\"out of memory\"");

	/* create struct cYAML root object */
	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	peer_root = cYAML_create_seq(root, "peer");
	if (peer_root == NULL)
		goto out;

	do {
		for (i = 0;; i++) {
			LIBCFS_IOC_INIT_V2(peer_info, pr_hdr);
			peer_info.pr_count = i;
			peer_info.pr_lnd_u.pr_peer_credits.cr_ncpt = j;
			rc = l_ioctl(LNET_DEV_ID,
				     IOC_LIBCFS_GET_PEER_INFO, &peer_info);
			if (rc != 0) {
				l_errno = errno;
				break;
			}

			if (ncpt_set != 0) {
				ncpt = peer_info.pr_lnd_u.pr_peer_credits.
					cr_ncpt;
				ncpt_set = true;
			}

			peer = cYAML_create_seq_item(peer_root);
			if (peer == NULL)
				goto out;

			if (first_seq == NULL)
				first_seq = peer;

			if (cYAML_create_string(peer, "nid",
						libcfs_nid2str
						 (peer_info.pr_nid)) == NULL)
				goto out;

			if (cYAML_create_string(peer, "state",
						peer_info.pr_lnd_u.
						  pr_peer_credits.
							cr_aliveness) ==
			    NULL)
				goto out;

			if (cYAML_create_number(peer, "refcount",
						peer_info.pr_lnd_u.
						  pr_peer_credits.
							cr_refcount) == NULL)
				goto out;

			if (cYAML_create_number(peer, "max_ni_tx_credits",
						peer_info.pr_lnd_u.
						  pr_peer_credits.
						    cr_ni_peer_tx_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer, "available_tx_credits",
						peer_info.pr_lnd_u.
						  pr_peer_credits.
						    cr_peer_tx_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer, "available_rtr_credits",
						peer_info.pr_lnd_u.
						  pr_peer_credits.
						    cr_peer_rtr_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer, "min_rtr_credits",
						peer_info.pr_lnd_u.
						  pr_peer_credits.
						    cr_peer_min_rtr_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer, "tx_q_num_of_buf",
						peer_info.pr_lnd_u.
						  pr_peer_credits.
						    cr_peer_tx_qnob)
			    == NULL)
				goto out;
		}

		if (l_errno != ENOENT) {
			snprintf(err_str,
				sizeof(err_str),
				"\"cannot get peer information: %s\"",
				strerror(l_errno));
			rc = -l_errno;
			goto out;
		}

		j++;
	} while (j < ncpt);

	/* print output iff show_rc is not provided */
	if (show_rc == NULL)
		cYAML_print_tree(root);

	snprintf(err_str, sizeof(err_str), "\"success\"");
	rc = LUSTRE_CFG_RC_NO_ERR;

out:
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		struct cYAML *show_node;
		/* find the peer node, if one doesn't exist then
		 * insert one.  Otherwise add to the one there
		 */
		show_node = cYAML_get_object_item(*show_rc,
						  "peer_credits");
		if (show_node != NULL && cYAML_is_sequence(show_node)) {
			cYAML_insert_child(show_node, first_seq);
			free(peer_root);
			free(root);
		} else if (show_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
					     peer_root);
			free(root);
		} else {
			cYAML_free_tree(root);
		}
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, "peer_credits", err_str,
			  err_rc);

	return rc;
}

int lustre_lnet_show_stats(int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc)
{
	struct lnet_ioctl_lnet_stats data;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	int l_errno;
	char err_str[LNET_MAX_STR_LEN];
	struct cYAML *root = NULL, *stats = NULL;

	snprintf(err_str, sizeof(err_str), "\"out of memory\"");

	LIBCFS_IOC_INIT_V2(data, st_hdr);

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_LNET_STATS, &data);
	if (rc != 0) {
		l_errno = errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get lnet statistics: %s\"",
			 strerror(l_errno));
		rc = -l_errno;
		goto out;
	}

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	stats = cYAML_create_object(root, "statistics");
	if (stats == NULL)
		goto out;

	if (cYAML_create_number(stats, "msgs_alloc",
				data.st_cntrs.msgs_alloc) == NULL)
		goto out;

	if (cYAML_create_number(stats, "msgs_max",
				data.st_cntrs.msgs_max) == NULL)
		goto out;

	if (cYAML_create_number(stats, "errors",
				data.st_cntrs.errors) == NULL)
		goto out;

	if (cYAML_create_number(stats, "send_count",
				data.st_cntrs.send_count) == NULL)
		goto out;

	if (cYAML_create_number(stats, "recv_count",
				data.st_cntrs.recv_count) == NULL)
		goto out;

	if (cYAML_create_number(stats, "route_count",
				data.st_cntrs.route_count) == NULL)
		goto out;

	if (cYAML_create_number(stats, "drop_count",
				data.st_cntrs.drop_count) == NULL)
		goto out;

	if (cYAML_create_number(stats, "send_length",
				data.st_cntrs.send_length) == NULL)
		goto out;

	if (cYAML_create_number(stats, "recv_length",
				data.st_cntrs.recv_length) == NULL)
		goto out;

	if (cYAML_create_number(stats, "route_length",
				data.st_cntrs.route_length) == NULL)
		goto out;

	if (cYAML_create_number(stats, "drop_length",
				data.st_cntrs.drop_length) == NULL)
		goto out;

	if (show_rc == NULL)
		cYAML_print_tree(root);

	snprintf(err_str, sizeof(err_str), "\"success\"");
out:
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		cYAML_insert_sibling((*show_rc)->cy_child,
					root->cy_child);
		free(root);
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, "statistics", err_str, err_rc);

	return rc;
}

typedef int (*cmd_handler_t)(struct cYAML *tree,
			     struct cYAML **show_rc,
			     struct cYAML **err_rc);

static int handle_yaml_config_route(struct cYAML *tree, struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	struct cYAML *net, *gw, *hop, *prio, *seq_no;

	net = cYAML_get_object_item(tree, "net");
	gw = cYAML_get_object_item(tree, "gateway");
	hop = cYAML_get_object_item(tree, "hop");
	prio = cYAML_get_object_item(tree, "priority");
	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_config_route((net) ? net->cy_valuestring : NULL,
					(gw) ? gw->cy_valuestring : NULL,
					(hop) ? hop->cy_valueint : -1,
					(prio) ? prio->cy_valueint : -1,
					(seq_no) ? seq_no->cy_valueint : -1,
					err_rc);
}

static int handle_yaml_config_net(struct cYAML *tree, struct cYAML **show_rc,
				  struct cYAML **err_rc)
{
	struct cYAML *net, *intf, *tunables, *seq_no,
	      *peer_to = NULL, *peer_buf_cr = NULL, *peer_cr = NULL,
	      *credits = NULL, *ip2net = NULL, *smp = NULL, *child;
	struct lnet_ioctl_config_lnd_tunables *lnd_tunables_p = NULL;
	struct lnet_ioctl_config_lnd_tunables lnd_tunables;
	char devs[LNET_MAX_STR_LEN];
	char *loc = devs;
	int size = LNET_MAX_STR_LEN;
	int num;
	bool intf_found = false;

	ip2net = cYAML_get_object_item(tree, "ip2net");
	net = cYAML_get_object_item(tree, "net");
	intf = cYAML_get_object_item(tree, "interfaces");
	if (intf != NULL) {
		/* grab all the interfaces */
		child = intf->cy_child;
		while (child != NULL && size > 0) {
			struct cYAML *lnd_params;

			if (child->cy_valuestring == NULL)
				goto ignore_child;

			if (loc > devs)
				num  = snprintf(loc, size, ",%s",
						child->cy_valuestring);
			else
				num = snprintf(loc, size, "%s",
					       child->cy_valuestring);
			size -= num;
			loc += num;
			intf_found = true;

			lnd_params = cYAML_get_object_item(intf,
							   "lnd tunables");
			if (lnd_params != NULL) {
				const char *dev_name = child->cy_valuestring;
				lnd_tunables_p = &lnd_tunables;

				lustre_interface_parse(lnd_params, dev_name,
						       lnd_tunables_p);
			}
ignore_child:
			child = child->cy_next;
		}
	}

	tunables = cYAML_get_object_item(tree, "tunables");
	if (tunables != NULL) {
		peer_to = cYAML_get_object_item(tunables, "peer_timeout");
		peer_cr = cYAML_get_object_item(tunables, "peer_credits");
		peer_buf_cr = cYAML_get_object_item(tunables,
						    "peer_buffer_credits");
		credits = cYAML_get_object_item(tunables, "credits");
		smp = cYAML_get_object_item(tunables, "CPT");
	}
	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_config_net((net) ? net->cy_valuestring : NULL,
				      (intf_found) ? devs : NULL,
				      (ip2net) ? ip2net->cy_valuestring : NULL,
				      (peer_to) ? peer_to->cy_valueint : -1,
				      (peer_cr) ? peer_cr->cy_valueint : -1,
				      (peer_buf_cr) ?
					peer_buf_cr->cy_valueint : -1,
				      (credits) ? credits->cy_valueint : -1,
				      (smp) ? smp->cy_valuestring : NULL,
				      (seq_no) ? seq_no->cy_valueint : -1,
				      lnd_tunables_p,
				      err_rc);
}

static int handle_yaml_config_buffers(struct cYAML *tree,
				      struct cYAML **show_rc,
				      struct cYAML **err_rc)
{
	int rc;
	struct cYAML *tiny, *small, *large, *seq_no;

	tiny = cYAML_get_object_item(tree, "tiny");
	small = cYAML_get_object_item(tree, "small");
	large = cYAML_get_object_item(tree, "large");
	seq_no = cYAML_get_object_item(tree, "seq_no");

	rc = lustre_lnet_config_buffers((tiny) ? tiny->cy_valueint : -1,
					(small) ? small->cy_valueint : -1,
					(large) ? large->cy_valueint : -1,
					(seq_no) ? seq_no->cy_valueint : -1,
					err_rc);

	return rc;
}

static int handle_yaml_config_routing(struct cYAML *tree,
				      struct cYAML **show_rc,
				      struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	struct cYAML *seq_no, *enable;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	enable = cYAML_get_object_item(tree, "enable");

	if (enable) {
		rc = lustre_lnet_enable_routing(enable->cy_valueint,
						(seq_no) ?
						    seq_no->cy_valueint : -1,
						err_rc);
	}

	return rc;
}

static int handle_yaml_del_route(struct cYAML *tree, struct cYAML **show_rc,
				 struct cYAML **err_rc)
{
	struct cYAML *net;
	struct cYAML *gw;
	struct cYAML *seq_no;

	net = cYAML_get_object_item(tree, "net");
	gw = cYAML_get_object_item(tree, "gateway");
	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_del_route((net) ? net->cy_valuestring : NULL,
				     (gw) ? gw->cy_valuestring : NULL,
				     (seq_no) ? seq_no->cy_valueint : -1,
				     err_rc);
}

static int handle_yaml_del_net(struct cYAML *tree, struct cYAML **show_rc,
			       struct cYAML **err_rc)
{
	struct cYAML *net, *seq_no;

	net = cYAML_get_object_item(tree, "net");
	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_del_net((net) ? net->cy_valuestring : NULL,
				   (seq_no) ? seq_no->cy_valueint : -1,
				   err_rc);
}

static int handle_yaml_del_routing(struct cYAML *tree, struct cYAML **show_rc,
				   struct cYAML **err_rc)
{
	struct cYAML *seq_no;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_enable_routing(0, (seq_no) ?
						seq_no->cy_valueint : -1,
					err_rc);
}

static int handle_yaml_show_route(struct cYAML *tree, struct cYAML **show_rc,
				  struct cYAML **err_rc)
{
	struct cYAML *net;
	struct cYAML *gw;
	struct cYAML *hop;
	struct cYAML *prio;
	struct cYAML *detail;
	struct cYAML *seq_no;

	net = cYAML_get_object_item(tree, "net");
	gw = cYAML_get_object_item(tree, "gateway");
	hop = cYAML_get_object_item(tree, "hop");
	prio = cYAML_get_object_item(tree, "priority");
	detail = cYAML_get_object_item(tree, "detail");
	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_show_route((net) ? net->cy_valuestring : NULL,
				      (gw) ? gw->cy_valuestring : NULL,
				      (hop) ? hop->cy_valueint : -1,
				      (prio) ? prio->cy_valueint : -1,
				      (detail) ? detail->cy_valueint : 0,
				      (seq_no) ? seq_no->cy_valueint : -1,
				      show_rc,
				      err_rc);
}

static int handle_yaml_show_net(struct cYAML *tree, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	struct cYAML *net, *detail, *seq_no;

	net = cYAML_get_object_item(tree, "net");
	detail = cYAML_get_object_item(tree, "detail");
	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_show_net((net) ? net->cy_valuestring : NULL,
				    (detail) ? detail->cy_valueint : 0,
				    (seq_no) ? seq_no->cy_valueint : -1,
				    show_rc,
				    err_rc);
}

static int handle_yaml_show_routing(struct cYAML *tree, struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	struct cYAML *seq_no;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_show_routing((seq_no) ? seq_no->cy_valueint : -1,
					show_rc, err_rc);
}

static int handle_yaml_show_credits(struct cYAML *tree, struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	struct cYAML *seq_no;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_show_peer_credits((seq_no) ?
						seq_no->cy_valueint : -1,
					     show_rc, err_rc);
}

static int handle_yaml_show_stats(struct cYAML *tree, struct cYAML **show_rc,
				  struct cYAML **err_rc)
{
	struct cYAML *seq_no;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_show_stats((seq_no) ? seq_no->cy_valueint : -1,
				      show_rc, err_rc);
}

struct lookup_cmd_hdlr_tbl {
	char *name;
	cmd_handler_t cb;
};

static struct lookup_cmd_hdlr_tbl lookup_config_tbl[] = {
	{"route", handle_yaml_config_route},
	{"net", handle_yaml_config_net},
	{"routing", handle_yaml_config_routing},
	{"buffers", handle_yaml_config_buffers},
	{NULL, NULL}
};

static struct lookup_cmd_hdlr_tbl lookup_del_tbl[] = {
	{"route", handle_yaml_del_route},
	{"net", handle_yaml_del_net},
	{"routing", handle_yaml_del_routing},
	{NULL, NULL}
};

static struct lookup_cmd_hdlr_tbl lookup_show_tbl[] = {
	{"route", handle_yaml_show_route},
	{"net", handle_yaml_show_net},
	{"buffers", handle_yaml_show_routing},
	{"routing", handle_yaml_show_routing},
	{"credits", handle_yaml_show_credits},
	{"statistics", handle_yaml_show_stats},
	{NULL, NULL}
};

static cmd_handler_t lookup_fn(char *key,
			       struct lookup_cmd_hdlr_tbl *tbl)
{
	int i;
	if (key == NULL)
		return NULL;

	for (i = 0; tbl[i].name != NULL; i++) {
		if (strncmp(key, tbl[i].name, strlen(tbl[i].name)) == 0)
			return tbl[i].cb;
	}

	return NULL;
}

static int lustre_yaml_cb_helper(char *f, struct lookup_cmd_hdlr_tbl *table,
				 struct cYAML **show_rc, struct cYAML **err_rc)
{
	struct cYAML *tree, *item = NULL, *head, *child;
	cmd_handler_t cb;
	char err_str[LNET_MAX_STR_LEN];
	int rc = LUSTRE_CFG_RC_NO_ERR, return_rc = LUSTRE_CFG_RC_NO_ERR;

	tree = cYAML_build_tree(f, NULL, 0, err_rc);
	if (tree == NULL)
		return LUSTRE_CFG_RC_BAD_PARAM;

	child = tree->cy_child;
	while (child != NULL) {
		cb = lookup_fn(child->cy_string, table);
		if (cb == NULL) {
			snprintf(err_str, sizeof(err_str),
				"\"call back for '%s' not found\"",
				child->cy_string);
			cYAML_build_error(LUSTRE_CFG_RC_BAD_PARAM, -1,
					"yaml", "helper", err_str, err_rc);
			goto out;
		}

		if (cYAML_is_sequence(child)) {
			while ((head = cYAML_get_next_seq_item(child, &item))
			       != NULL) {
				rc = cb(head, show_rc, err_rc);
				if (rc != LUSTRE_CFG_RC_NO_ERR)
					return_rc = rc;
			}
		} else {
			rc = cb(child, show_rc, err_rc);
			if (rc != LUSTRE_CFG_RC_NO_ERR)
				return_rc = rc;
		}
		item = NULL;
		child = child->cy_next;
	}

out:
	cYAML_free_tree(tree);

	return return_rc;
}

int lustre_yaml_config(char *f, struct cYAML **err_rc)
{
	return lustre_yaml_cb_helper(f, lookup_config_tbl,
				     NULL, err_rc);
}

int lustre_yaml_del(char *f, struct cYAML **err_rc)
{
	return lustre_yaml_cb_helper(f, lookup_del_tbl,
				     NULL, err_rc);
}

int lustre_yaml_show(char *f, struct cYAML **show_rc, struct cYAML **err_rc)
{
	return lustre_yaml_cb_helper(f, lookup_show_tbl,
				     show_rc, err_rc);
}
