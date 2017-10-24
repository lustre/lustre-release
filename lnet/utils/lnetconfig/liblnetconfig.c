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
#include <byteswap.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libcfs/util/ioctl.h>
#include <lnet/lnetctl.h>
#include <lnet/socklnd.h>
#include "liblnd.h"
#include <lnet/lnet.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include "liblnetconfig.h"
#include "cyaml.h"

#define CONFIG_CMD		"configure"
#define UNCONFIG_CMD		"unconfigure"
#define ADD_CMD			"add"
#define DEL_CMD			"del"
#define SHOW_CMD		"show"
#define DBG_CMD			"dbg"

/*
 * lustre_lnet_ip_range_descr
 *	Describes an IP range.
 *	Each octect is an expression
 */
struct lustre_lnet_ip_range_descr {
	struct list_head ipr_entry;
	struct list_head ipr_expr;
};

/*
 * lustre_lnet_ip2nets
 *	Describes an ip2nets rule. This can be on a list of rules.
 */
struct lustre_lnet_ip2nets {
	struct lnet_dlc_network_descr ip2nets_net;
	struct list_head ip2nets_ip_ranges;
};

/*
 * free_intf_descr
 *	frees the memory allocated for an intf descriptor.
 */
void free_intf_descr(struct lnet_dlc_intf_descr *intf_descr)
{
	if (!intf_descr)
		return;

	if (intf_descr->cpt_expr != NULL)
		cfs_expr_list_free(intf_descr->cpt_expr);
	free(intf_descr);
}

/*
 * lustre_lnet_add_ip_range
 * Formatting:
 *	given a string of the format:
 *	<expr.expr.expr.expr> parse each expr into
 *	a lustre_lnet_ip_range_descr structure and insert on the list.
 *
 *	This function is called from
 *		YAML on each ip-range.
 *		As a result of lnetctl command
 *		When building a NID or P2P selection rules
 */
int lustre_lnet_add_ip_range(struct list_head *list, char *str_ip_range)
{
	struct lustre_lnet_ip_range_descr *ip_range;
	int rc;

	ip_range = calloc(1, sizeof(*ip_range));
	if (ip_range == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	INIT_LIST_HEAD(&ip_range->ipr_entry);
	INIT_LIST_HEAD(&ip_range->ipr_expr);

	rc = cfs_ip_addr_parse(str_ip_range, strlen(str_ip_range),
			       &ip_range->ipr_expr);
	if (rc != 0)
		return LUSTRE_CFG_RC_BAD_PARAM;

	list_add_tail(&ip_range->ipr_entry, list);

	return LUSTRE_CFG_RC_NO_ERR;
}

int lustre_lnet_add_intf_descr(struct list_head *list, char *intf, int len)
{
	char *open_sq_bracket = NULL, *close_sq_bracket = NULL,
	     *intf_name;
	struct lnet_dlc_intf_descr *intf_descr = NULL;
	int rc;
	char intf_string[LNET_MAX_STR_LEN];

	if (len >= LNET_MAX_STR_LEN)
		return LUSTRE_CFG_RC_BAD_PARAM;

	strncpy(intf_string, intf, len);
	intf_string[len] = '\0';

	intf_descr = calloc(1, sizeof(*intf_descr));
	if (intf_descr == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	INIT_LIST_HEAD(&intf_descr->intf_on_network);

	intf_name = intf_string;
	open_sq_bracket = strchr(intf_string, '[');
	if (open_sq_bracket != NULL) {
		close_sq_bracket = strchr(intf_string, ']');
		if (close_sq_bracket == NULL) {
			free(intf_descr);
			return LUSTRE_CFG_RC_BAD_PARAM;
		}
		rc = cfs_expr_list_parse(open_sq_bracket,
					 strlen(open_sq_bracket), 0, UINT_MAX,
					 &intf_descr->cpt_expr);
		if (rc < 0) {
			free(intf_descr);
			return LUSTRE_CFG_RC_BAD_PARAM;
		}
		strncpy(intf_descr->intf_name, intf_name,
			open_sq_bracket - intf_name);
		intf_descr->intf_name[open_sq_bracket - intf_name] = '\0';
	} else {
		strcpy(intf_descr->intf_name, intf_name);
		intf_descr->cpt_expr = NULL;
	}

	list_add_tail(&intf_descr->intf_on_network, list);

	return LUSTRE_CFG_RC_NO_ERR;
}

void lustre_lnet_init_nw_descr(struct lnet_dlc_network_descr *nw_descr)
{
	if (nw_descr != NULL) {
		INIT_LIST_HEAD(&nw_descr->network_on_rule);
		INIT_LIST_HEAD(&nw_descr->nw_intflist);
	}
}

int lustre_lnet_parse_nids(char *nids, char **array, int size,
			   char ***out_array)
{
	int num_nids = 0;
	char *comma = nids, *cur, *entry;
	char **new_array;
	int i, len, start = 0, finish = 0;

	if (nids == NULL || strlen(nids) == 0)
		return size;

	/* count the number or new nids, by counting the number of commas */
	while (comma) {
		comma = strchr(comma, ',');
		if (comma) {
			comma++;
			num_nids++;
		} else {
			num_nids++;
		}
	}

	/*
	 * if the array is not NULL allocate a large enough array to house
	 * the old and new entries
	 */
	new_array = calloc(sizeof(char*),
			   (size > 0) ? size + num_nids : num_nids);

	if (!new_array)
		goto failed;

	/* parse our the new nids and add them to the tail of the array */
	comma = nids;
	cur = nids;
	start = (size > 0) ? size: 0;
	finish = (size > 0) ? size + num_nids : num_nids;
	for (i = start; i < finish; i++) {
		comma = strchr(comma, ',');
		if (!comma)
			/*
			 * the length of the string to be parsed out is
			 * from cur to end of string. So it's good enough
			 * to strlen(cur)
			 */
			len = strlen(cur) + 1;
		else
			/* length of the string is comma - cur */
			len = (comma - cur) + 1;

		entry = calloc(1, len);
		if (!entry) {
			finish = i > 0 ? i - 1: 0;
			goto failed;
		}
		strncpy(entry, cur, len - 1);
		entry[len] = '\0';
		new_array[i] = entry;
		if (comma) {
			comma++;
			cur = comma;
		}
	}

	/* add the old entries in the array and delete the old array*/
	for (i = 0; i < size; i++)
		new_array[i] = array[i];

	if (array)
		free(array);

	*out_array = new_array;

	return finish;

failed:
	for (i = start; i < finish; i++)
		free(new_array[i]);
	if (new_array)
		free(new_array);

	return size;
}

/*
 * format expected:
 *	<intf>[<expr>], <intf>[<expr>],..
 */
int lustre_lnet_parse_interfaces(char *intf_str,
				 struct lnet_dlc_network_descr *nw_descr)
{
	char *open_square;
	char *close_square;
	char *comma;
	char *cur = intf_str, *next = NULL;
	char *end = intf_str + strlen(intf_str);
	int rc, len;
	struct lnet_dlc_intf_descr *intf_descr, *tmp;

	if (nw_descr == NULL)
		return LUSTRE_CFG_RC_BAD_PARAM;

	while (cur < end) {
		open_square = strchr(cur, '[');
		if (open_square != NULL) {
			close_square = strchr(cur, ']');
			if (close_square == NULL) {
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				goto failed;
			}

			comma = strchr(cur, ',');
			if (comma != NULL && comma > close_square) {
				next = comma + 1;
				len = next - close_square;
			} else {
				len = strlen(cur);
				next = cur + len;
			}
		} else {
			comma = strchr(cur, ',');
			if (comma != NULL) {
				next = comma + 1;
				len = comma - cur;
			} else {
				len = strlen(cur);
				next = cur + len;
			}
		}

		rc = lustre_lnet_add_intf_descr(&nw_descr->nw_intflist, cur, len);
		if (rc != LUSTRE_CFG_RC_NO_ERR)
			goto failed;

		cur = next;
	}

	return LUSTRE_CFG_RC_NO_ERR;

failed:
	list_for_each_entry_safe(intf_descr, tmp, &nw_descr->nw_intflist,
				 intf_on_network) {
		list_del(&intf_descr->intf_on_network);
		free_intf_descr(intf_descr);
	}

	return rc;
}

int lustre_lnet_config_lib_init(void)
{
	return register_ioc_dev(LNET_DEV_ID, LNET_DEV_PATH);
}

void lustre_lnet_config_lib_uninit(void)
{
	unregister_ioc_dev(LNET_DEV_ID);
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

static lnet_nid_t *allocate_create_nid_array(char **nids, __u32 num_nids,
					     char *err_str)
{
	lnet_nid_t *array = NULL;
	__u32 i;

	if (!nids || num_nids == 0) {
		snprintf(err_str, LNET_MAX_STR_LEN, "no NIDs to add");
		return NULL;
	}

	array = calloc(sizeof(*array) * num_nids, 1);
	if (array == NULL) {
		snprintf(err_str, LNET_MAX_STR_LEN, "out of memory");
		return NULL;
	}

	for (i = 0; i < num_nids; i++) {
		array[i] = libcfs_str2nid(nids[i]);
		if (array[i] == LNET_NID_ANY) {
			free(array);
			snprintf(err_str, LNET_MAX_STR_LEN,
				 "bad NID: '%s'",
				 nids[i]);
			return NULL;
		}
	}

	return array;
}

static int dispatch_peer_ni_cmd(lnet_nid_t pnid, lnet_nid_t nid, __u32 cmd,
				struct lnet_ioctl_peer_cfg *data,
				char *err_str, char *cmd_str)
{
	int rc;

	data->prcfg_prim_nid = pnid;
	data->prcfg_cfg_nid = nid;

	rc = l_ioctl(LNET_DEV_ID, cmd, data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			LNET_MAX_STR_LEN,
			"\"cannot %s peer ni: %s\"",
			(cmd_str) ? cmd_str : "add", strerror(errno));
	}

	return rc;
}

int lustre_lnet_config_peer_nid(char *pnid, char **nid, int num_nids,
				bool mr, int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_peer_cfg data;
	lnet_nid_t prim_nid = LNET_NID_ANY;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	int idx = 0;
	bool nid0_used = false;
	char err_str[LNET_MAX_STR_LEN] = {0};
	lnet_nid_t *nids = allocate_create_nid_array(nid, num_nids, err_str);

	if (pnid) {
		prim_nid = libcfs_str2nid(pnid);
		if (prim_nid == LNET_NID_ANY) {
			snprintf(err_str, sizeof(err_str),
				 "bad key NID: '%s'",
				 pnid);
			rc = LUSTRE_CFG_RC_MISSING_PARAM;
			goto out;
		}
	} else if (!nids || nids[0] == LNET_NID_ANY) {
		snprintf(err_str, sizeof(err_str),
			 "no NIDs provided for configuration");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	} else {
		prim_nid = LNET_NID_ANY;
	}

	snprintf(err_str, sizeof(err_str), "\"Success\"");

	LIBCFS_IOC_INIT_V2(data, prcfg_hdr);
	data.prcfg_mr = mr;

	/*
	 * if prim_nid is not specified use the first nid in the list of
	 * nids provided as the prim_nid. NOTE: on entering 'if' we must
	 * have at least 1 NID
	 */
	if (prim_nid == LNET_NID_ANY) {
		nid0_used = true;
		prim_nid = nids[0];
	}

	/* Create the prim_nid first */
	rc = dispatch_peer_ni_cmd(prim_nid, LNET_NID_ANY,
				  IOC_LIBCFS_ADD_PEER_NI,
				  &data, err_str, "add");

	if (rc != 0)
		goto out;

	/* add the rest of the nids to the key nid if any are available */
	for (idx = nid0_used ? 1 : 0 ; nids && idx < num_nids; idx++) {
		/*
		 * If prim_nid is not provided then the first nid in the
		 * list becomes the prim_nid. First time round the loop use
		 * LNET_NID_ANY for the first parameter, then use nid[0]
		 * as the key nid after wards
		 */
		rc = dispatch_peer_ni_cmd(prim_nid, nids[idx],
					  IOC_LIBCFS_ADD_PEER_NI, &data,
					  err_str, "add");

		if (rc != 0)
			goto out;
	}

out:
	if (nids != NULL)
		free(nids);
	cYAML_build_error(rc, seq_no, ADD_CMD, "peer_ni", err_str, err_rc);
	return rc;
}

int lustre_lnet_del_peer_nid(char *pnid, char **nid, int num_nids,
			     int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_peer_cfg data;
	lnet_nid_t prim_nid;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	int idx = 0;
	char err_str[LNET_MAX_STR_LEN] = {0};
	lnet_nid_t *nids = allocate_create_nid_array(nid, num_nids, err_str);

	if (pnid == NULL) {
		snprintf(err_str, sizeof(err_str),
			 "\"Primary nid is not provided\"");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	} else {
		prim_nid = libcfs_str2nid(pnid);
		if (prim_nid == LNET_NID_ANY) {
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			snprintf(err_str, sizeof(err_str),
				 "bad key NID: '%s'",
				 pnid);
			goto out;
		}
	}

	snprintf(err_str, sizeof(err_str), "\"Success\"");

	LIBCFS_IOC_INIT_V2(data, prcfg_hdr);
	if (!nids || nids[0] == LNET_NID_ANY) {
		rc = dispatch_peer_ni_cmd(prim_nid, LNET_NID_ANY,
					  IOC_LIBCFS_DEL_PEER_NI,
					  &data, err_str, "del");
		goto out;
	}

	for (idx = 0; nids && idx < num_nids; idx++) {
		rc = dispatch_peer_ni_cmd(prim_nid, nids[idx],
					  IOC_LIBCFS_DEL_PEER_NI, &data,
					  err_str, "del");

		if (rc != 0)
			goto out;
	}

out:
	if (nids != NULL)
		free(nids);
	cYAML_build_error(rc, seq_no, DEL_CMD, "peer_ni", err_str, err_rc);
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
						(int) data.cfg_config_u.
						cfg_route.rtr_hop) ==
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

static int socket_intf_query(int request, char *intf,
			     struct ifreq *ifr)
{
	int rc = 0;
	int sockfd;

	if (strlen(intf) >= IFNAMSIZ || ifr == NULL)
		return LUSTRE_CFG_RC_BAD_PARAM;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return LUSTRE_CFG_RC_BAD_PARAM;

	strcpy(ifr->ifr_name, intf);
	rc = ioctl(sockfd, request, ifr);
	if (rc != 0)
		rc = LUSTRE_CFG_RC_BAD_PARAM;

	close(sockfd);

	return rc;
}

/*
 * for each interface in the array of interfaces find the IP address of
 * that interface, create its nid and add it to an array of NIDs.
 * Stop if any of the interfaces is down
 */
static int lustre_lnet_intf2nids(struct lnet_dlc_network_descr *nw,
				 lnet_nid_t **nids, __u32 *nnids)
{
	int i = 0, count = 0, rc;
	struct ifreq ifr;
	__u32 ip;
	struct lnet_dlc_intf_descr *intf;

	if (nw == NULL || nids == NULL)
		return LUSTRE_CFG_RC_BAD_PARAM;

	list_for_each_entry(intf, &nw->nw_intflist, intf_on_network)
		count++;

	*nids = calloc(count, sizeof(lnet_nid_t));
	if (*nids == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	list_for_each_entry(intf, &nw->nw_intflist, intf_on_network) {
		memset(&ifr, 0, sizeof(ifr));
		rc = socket_intf_query(SIOCGIFFLAGS, intf->intf_name, &ifr);
		if (rc != 0)
			goto failed;

		if ((ifr.ifr_flags & IFF_UP) == 0) {
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			goto failed;
		}

		memset(&ifr, 0, sizeof(ifr));
		rc = socket_intf_query(SIOCGIFADDR, intf->intf_name, &ifr);
		if (rc != 0)
			goto failed;

		ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
		ip = bswap_32(ip);
		(*nids)[i] = LNET_MKNID(nw->nw_id, ip);
		i++;
	}

	*nnids = count;

	return 0;

failed:
	free(*nids);
	*nids = NULL;
	return rc;
}

/*
 * called repeatedly until a match or no more ip range
 * What do you have?
 *	ip_range expression
 *	interface list with all the interface names.
 *	all the interfaces in the system.
 *
 *	try to match the ip_range expr to one of the interfaces' IPs in
 *	the system. If we hit a patch for an interface. Check if that
 *	interface name is in the list.
 *
 *	If there are more than one interface in the list, then make sure
 *	that the IPs for all of these interfaces match the ip ranges
 *	given.
 *
 *	for each interface in intf_list
 *		look up the intf name in ifa
 *		if not there then no match
 *		check ip obtained from ifa against a match to any of the
 *		ip_ranges given.
 *		If no match, then fail
 *
 *	The result is that all the interfaces have to match.
 */
int lustre_lnet_match_ip_to_intf(struct ifaddrs *ifa,
				 struct list_head *intf_list,
				 struct list_head *ip_ranges)
{
	int rc;
	__u32 ip;
	struct lnet_dlc_intf_descr *intf_descr, *tmp;
	struct ifaddrs *ifaddr = ifa;
	struct lustre_lnet_ip_range_descr *ip_range;
	int family;

	/*
	 * if there are no explicit interfaces, and no ip ranges, then
	 * configure the first tcp interface we encounter.
	 */
	if (list_empty(intf_list) && list_empty(ip_ranges)) {
		for (ifaddr = ifa; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
			if (ifaddr->ifa_addr == NULL)
				continue;

			if ((ifaddr->ifa_flags & IFF_UP) == 0)
				continue;

			family = ifaddr->ifa_addr->sa_family;
			if (family == AF_INET &&
			    strcmp(ifaddr->ifa_name, "lo") != 0) {
				rc = lustre_lnet_add_intf_descr
					(intf_list, ifaddr->ifa_name,
					strlen(ifaddr->ifa_name));

				if (rc != LUSTRE_CFG_RC_NO_ERR)
					return rc;

				return LUSTRE_CFG_RC_MATCH;
			}
		}
		return LUSTRE_CFG_RC_NO_MATCH;
	}

	/*
	 * First interface which matches an IP pattern will be used
	 */
	if (list_empty(intf_list)) {
		/*
		 * no interfaces provided in the rule, but an ip range is
		 * provided, so try and match an interface to the ip
		 * range.
		 */
		for (ifaddr = ifa; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
			if (ifaddr->ifa_addr == NULL)
				continue;

			if ((ifaddr->ifa_flags & IFF_UP) == 0)
				continue;

			family = ifaddr->ifa_addr->sa_family;
			if (family == AF_INET) {
				ip = ((struct sockaddr_in *)ifaddr->ifa_addr)->
					sin_addr.s_addr;

				list_for_each_entry(ip_range, ip_ranges,
						    ipr_entry) {
					rc = cfs_ip_addr_match(bswap_32(ip),
							&ip_range->ipr_expr);
					if (!rc)
						continue;

					rc = lustre_lnet_add_intf_descr
					  (intf_list, ifaddr->ifa_name,
					   strlen(ifaddr->ifa_name));

					if (rc != LUSTRE_CFG_RC_NO_ERR)
						return rc;
				}
			}
		}

		if (!list_empty(intf_list))
			return LUSTRE_CFG_RC_MATCH;

		return LUSTRE_CFG_RC_NO_MATCH;
	}

	/*
	 * If an interface is explicitly specified the ip-range might or
	 * might not be specified. if specified the interface needs to match the
	 * ip-range. If no ip-range then the interfaces are
	 * automatically matched if they are all up.
	 * If > 1 interfaces all the interfaces must match for the NI to
	 * be configured.
	 */
	list_for_each_entry_safe(intf_descr, tmp, intf_list, intf_on_network) {
		for (ifaddr = ifa; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
			if (ifaddr->ifa_addr == NULL)
				continue;

			family = ifaddr->ifa_addr->sa_family;
			if (family == AF_INET &&
			    strcmp(intf_descr->intf_name,
				   ifaddr->ifa_name) == 0)
				break;
		}

		if (ifaddr == NULL) {
			list_del(&intf_descr->intf_on_network);
			free_intf_descr(intf_descr);
			continue;
		}

		if ((ifaddr->ifa_flags & IFF_UP) == 0) {
			list_del(&intf_descr->intf_on_network);
			free_intf_descr(intf_descr);
			continue;
		}

		ip = ((struct sockaddr_in *)ifaddr->ifa_addr)->sin_addr.s_addr;

		rc = 1;
		list_for_each_entry(ip_range, ip_ranges, ipr_entry) {
			rc = cfs_ip_addr_match(bswap_32(ip), &ip_range->ipr_expr);
			if (rc)
				break;
		}

		if (!rc) {
			/* no match for this interface */
			list_del(&intf_descr->intf_on_network);
			free_intf_descr(intf_descr);
		}
	}

	return LUSTRE_CFG_RC_MATCH;
}

int lustre_lnet_resolve_ip2nets_rule(struct lustre_lnet_ip2nets *ip2nets,
				     lnet_nid_t **nids, __u32 *nnids)
{
	struct ifaddrs *ifa;
	int rc = LUSTRE_CFG_RC_NO_ERR;

	rc = getifaddrs(&ifa);
	if (rc < 0)
		return -errno;

	rc = lustre_lnet_match_ip_to_intf(ifa,
					  &ip2nets->ip2nets_net.nw_intflist,
					  &ip2nets->ip2nets_ip_ranges);
	if (rc != LUSTRE_CFG_RC_MATCH) {
		freeifaddrs(ifa);
		return rc;
	}

	rc = lustre_lnet_intf2nids(&ip2nets->ip2nets_net, nids, nnids);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		*nids = NULL;
		*nnids = 0;
	}

	freeifaddrs(ifa);

	return rc;
}

static int
lustre_lnet_ioctl_config_ni(struct list_head *intf_list,
			    struct lnet_ioctl_config_lnd_tunables *tunables,
			    struct cfs_expr_list *global_cpts,
			    lnet_nid_t *nids, char *err_str)
{
	char *data;
	struct lnet_ioctl_config_ni *conf;
	struct lnet_ioctl_config_lnd_tunables *tun = NULL;
	int rc = LUSTRE_CFG_RC_NO_ERR, i = 0;
	size_t len;
	int count;
	struct lnet_dlc_intf_descr *intf_descr;
	__u32 *cpt_array;
	struct cfs_expr_list *cpt_expr;

	list_for_each_entry(intf_descr, intf_list,
			    intf_on_network) {
		if (tunables != NULL)
			len = sizeof(struct lnet_ioctl_config_ni) +
			      sizeof(struct lnet_ioctl_config_lnd_tunables);
		else
			len = sizeof(struct lnet_ioctl_config_ni);

		data = calloc(1, len);
		if (!data)
			return LUSTRE_CFG_RC_OUT_OF_MEM;
		conf = (struct lnet_ioctl_config_ni*) data;
		if (tunables != NULL)
			tun = (struct lnet_ioctl_config_lnd_tunables*)
				conf->lic_bulk;

		LIBCFS_IOC_INIT_V2(*conf, lic_cfg_hdr);
		conf->lic_cfg_hdr.ioc_len = len;
		conf->lic_nid = nids[i];
		strncpy(conf->lic_ni_intf[0], intf_descr->intf_name,
			LNET_MAX_STR_LEN);

		if (intf_descr->cpt_expr != NULL)
			cpt_expr = intf_descr->cpt_expr;
		else if (global_cpts != NULL)
			cpt_expr = global_cpts;
		else
			cpt_expr = NULL;

		if (cpt_expr != NULL) {
			count = cfs_expr_list_values(cpt_expr,
						     LNET_MAX_SHOW_NUM_CPT,
						     &cpt_array);
			if (count > 0) {
				memcpy(conf->lic_cpts, cpt_array,
				       sizeof(cpt_array[0]) * LNET_MAX_STR_LEN);
				free(cpt_array);
			} else {
				count = 0;
			}
		} else {
			count = 0;
		}

		conf->lic_ncpts = count;

		if (tunables != NULL)
			memcpy(tun, tunables, sizeof(*tunables));

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_LOCAL_NI, data);
		if (rc < 0) {
			rc = -errno;
			snprintf(err_str,
				 LNET_MAX_STR_LEN,
				 "\"cannot add network: %s\"", strerror(errno));
			free(data);
			return rc;
		}
		free(data);
		i++;
	}

	return LUSTRE_CFG_RC_NO_ERR;
}

int
lustre_lnet_config_ip2nets(struct lustre_lnet_ip2nets *ip2nets,
			   struct lnet_ioctl_config_lnd_tunables *tunables,
			   struct cfs_expr_list *global_cpts,
			   int seq_no, struct cYAML **err_rc)
{
	lnet_nid_t *nids = NULL;
	__u32 nnids = 0;
	int rc;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"success\"");

	if (!ip2nets) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"incomplete ip2nets information\"");
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	/*
	 * call below function to resolve the rules into a list of nids.
	 * The memory is allocated in that function then freed here when
	 * it's no longer needed.
	 */
	rc = lustre_lnet_resolve_ip2nets_rule(ip2nets, &nids, &nnids);
	if (rc != LUSTRE_CFG_RC_NO_ERR && rc != LUSTRE_CFG_RC_MATCH) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot resolve ip2nets rule\"");
		goto out;
	}

	if (list_empty(&ip2nets->ip2nets_net.nw_intflist)) {
		snprintf(err_str, sizeof(err_str),
			 "\"no interfaces match ip2nets rules\"");
		goto free_nids_out;
	}

	rc = lustre_lnet_ioctl_config_ni(&ip2nets->ip2nets_net.nw_intflist,
					 tunables, global_cpts, nids,
					 err_str);

free_nids_out:
	free(nids);

out:
	cYAML_build_error(rc, seq_no, ADD_CMD, "ip2nets", err_str, err_rc);
	return rc;
}

int lustre_lnet_config_ni(struct lnet_dlc_network_descr *nw_descr,
			  struct cfs_expr_list *global_cpts,
			  char *ip2net,
			  struct lnet_ioctl_config_lnd_tunables *tunables,
			  int seq_no, struct cYAML **err_rc)
{
	char *data = NULL;
	struct lnet_ioctl_config_ni *conf;
	struct lnet_ioctl_config_lnd_tunables *tun = NULL;
	char buf[LNET_MAX_STR_LEN];
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];
	lnet_nid_t *nids = NULL;
	__u32 nnids = 0;
	size_t len;
	int count;
	struct lnet_dlc_intf_descr *intf_descr, *tmp;
	__u32 *cpt_array;

	snprintf(err_str, sizeof(err_str), "\"success\"");

	if (ip2net == NULL && nw_descr == NULL) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"mandatory parameters not specified.\"");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
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

	if (ip2net != NULL) {
		if (tunables != NULL)
			len = sizeof(struct lnet_ioctl_config_ni) +
			      sizeof(struct lnet_ioctl_config_lnd_tunables);
		else
			len = sizeof(struct lnet_ioctl_config_ni);
		data = calloc(1, len);
		if (!data) {
			rc = LUSTRE_CFG_RC_OUT_OF_MEM;
			goto out;
		}
		conf = (struct lnet_ioctl_config_ni*) data;
		if (tunables != NULL)
			tun = (struct lnet_ioctl_config_lnd_tunables*)
				(data + sizeof(*conf));

		LIBCFS_IOC_INIT_V2(*conf, lic_cfg_hdr);
		conf->lic_cfg_hdr.ioc_len = len;
		strncpy(conf->lic_legacy_ip2nets, ip2net,
			LNET_MAX_STR_LEN);

		if (global_cpts != NULL) {
			count = cfs_expr_list_values(global_cpts,
						     LNET_MAX_SHOW_NUM_CPT,
						     &cpt_array);
			if (count > 0) {
				memcpy(conf->lic_cpts, cpt_array,
				       sizeof(cpt_array[0]) * LNET_MAX_STR_LEN);
				free(cpt_array);
			} else {
				count = 0;
			}
		} else {
			count = 0;
		}

		conf->lic_ncpts = count;

		if (tunables != NULL)
			memcpy(tun, tunables, sizeof(*tunables));

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_LOCAL_NI, data);
		if (rc < 0) {
			rc = -errno;
			snprintf(err_str,
				sizeof(err_str),
				"\"cannot add network: %s\"", strerror(errno));
			goto out;
		}

		goto out;
	}

	if (LNET_NETTYP(nw_descr->nw_id) == LOLND) {
		rc = LUSTRE_CFG_RC_NO_ERR;
		goto out;
	}

	if (nw_descr->nw_id == LNET_NIDNET(LNET_NID_ANY)) {
		snprintf(err_str,
			sizeof(err_str),
			"\"cannot parse net '%s'\"",
			libcfs_net2str(nw_descr->nw_id));
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	if (list_empty(&nw_descr->nw_intflist)) {
		snprintf(err_str,
			sizeof(err_str),
			"\"no interface name provided\"");
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	rc = lustre_lnet_intf2nids(nw_descr, &nids, &nnids);
	if (rc != 0) {
		snprintf(err_str, sizeof(err_str),
			 "\"bad parameter\"");
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	rc = lustre_lnet_ioctl_config_ni(&nw_descr->nw_intflist,
					 tunables, global_cpts, nids,
					 err_str);

out:
	if (nw_descr != NULL) {
		list_for_each_entry_safe(intf_descr, tmp,
					 &nw_descr->nw_intflist,
					 intf_on_network) {
			list_del(&intf_descr->intf_on_network);
			free_intf_descr(intf_descr);
		}
	}

	cYAML_build_error(rc, seq_no, ADD_CMD, "net", err_str, err_rc);

	if (nids)
		free(nids);

	if (data)
		free(data);

	return rc;
}

int lustre_lnet_del_ni(struct lnet_dlc_network_descr *nw_descr,
		       int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_config_ni data;
	int rc = LUSTRE_CFG_RC_NO_ERR, i;
	char err_str[LNET_MAX_STR_LEN];
	lnet_nid_t *nids = NULL;
	__u32 nnids = 0;
	struct lnet_dlc_intf_descr *intf_descr, *tmp;

	snprintf(err_str, sizeof(err_str), "\"success\"");

	if (nw_descr == NULL) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"missing mandatory parameter\"");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	}

	if (LNET_NETTYP(nw_descr->nw_id) == LOLND)
		return LUSTRE_CFG_RC_NO_ERR;

	if (nw_descr->nw_id == LNET_NIDNET(LNET_NID_ANY)) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot parse net '%s'\"",
			 libcfs_net2str(nw_descr->nw_id));
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	rc = lustre_lnet_intf2nids(nw_descr, &nids, &nnids);
	if (rc != 0) {
		snprintf(err_str, sizeof(err_str),
			 "\"bad parameter\"");
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	/*
	 * no interfaces just the nw_id is specified
	 */
	if (nnids == 0) {
		nids = calloc(1, sizeof(*nids));
		if (nids == NULL) {
			snprintf(err_str, sizeof(err_str),
				"\"out of memory\"");
			rc = LUSTRE_CFG_RC_OUT_OF_MEM;
			goto out;
		}
		nids[0] = LNET_MKNID(nw_descr->nw_id, 0);
		nnids = 1;
	}

	for (i = 0; i < nnids; i++) {
		LIBCFS_IOC_INIT_V2(data, lic_cfg_hdr);
		data.lic_nid = nids[i];

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_LOCAL_NI, &data);
		if (rc < 0) {
			rc = -errno;
			snprintf(err_str,
				sizeof(err_str),
				"\"cannot del network: %s\"", strerror(errno));
		}
	}

	list_for_each_entry_safe(intf_descr, tmp, &nw_descr->nw_intflist,
				 intf_on_network) {
		list_del(&intf_descr->intf_on_network);
		free_intf_descr(intf_descr);
	}

out:
	cYAML_build_error(rc, seq_no, DEL_CMD, "net", err_str, err_rc);

	if (nids != NULL)
		free(nids);

	return rc;
}

int lustre_lnet_show_net(char *nw, int detail, int seq_no,
			 struct cYAML **show_rc, struct cYAML **err_rc)
{
	char *buf;
	struct lnet_ioctl_config_ni *ni_data;
	struct lnet_ioctl_config_lnd_tunables *lnd;
	struct lnet_ioctl_element_stats *stats;
	__u32 net = LNET_NIDNET(LNET_NID_ANY);
	__u32 prev_net = LNET_NIDNET(LNET_NID_ANY);
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM, i, j;
	int l_errno = 0;
	struct cYAML *root = NULL, *tunables = NULL,
		*net_node = NULL, *interfaces = NULL,
		*item = NULL, *first_seq = NULL,
		*tmp = NULL, *statistics = NULL;
	int str_buf_len = LNET_MAX_SHOW_NUM_CPT * 2;
	char str_buf[str_buf_len];
	char *pos;
	char err_str[LNET_MAX_STR_LEN];
	bool exist = false, new_net = true;
	int net_num = 0;
	size_t buf_size = sizeof(*ni_data) + sizeof(*lnd) + sizeof(*stats);

	snprintf(err_str, sizeof(err_str), "\"out of memory\"");

	buf = calloc(1, buf_size);
	if (buf == NULL)
		goto out;

	ni_data = (struct lnet_ioctl_config_ni *)buf;

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
		__u32 rc_net;

		memset(buf, 0, buf_size);

		LIBCFS_IOC_INIT_V2(*ni_data, lic_cfg_hdr);
		/*
		 * set the ioc_len to the proper value since INIT assumes
		 * size of data
		 */
		ni_data->lic_cfg_hdr.ioc_len = buf_size;
		ni_data->lic_idx = i;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_LOCAL_NI, ni_data);
		if (rc != 0) {
			l_errno = errno;
			break;
		}

		rc_net = LNET_NIDNET(ni_data->lic_nid);

		/* filter on provided data */
		if (net != LNET_NIDNET(LNET_NID_ANY) &&
		    net != rc_net)
			continue;

		/* default rc to -1 in case we hit the goto */
		rc = -1;
		exist = true;

		stats = (struct lnet_ioctl_element_stats *)ni_data->lic_bulk;
		lnd = (struct lnet_ioctl_config_lnd_tunables *)
			(ni_data->lic_bulk + sizeof(*stats));

		if (rc_net != prev_net) {
			prev_net = rc_net;
			new_net = true;
			net_num++;
		}

		if (new_net) {
			if (!cYAML_create_string(net_node, "net type",
						 libcfs_net2str(rc_net)))
				goto out;

			tmp = cYAML_create_seq(net_node, "local NI(s)");
			if (tmp == NULL)
				goto out;
			new_net = false;
		}

		/* create the tree to be printed. */
		item = cYAML_create_seq_item(tmp);
		if (item == NULL)
			goto out;

		if (first_seq == NULL)
			first_seq = item;

		if (cYAML_create_string(item, "nid",
					libcfs_nid2str(ni_data->lic_nid)) == NULL)
			goto out;

		if (cYAML_create_string(item,
					"status",
					(ni_data->lic_status ==
					  LNET_NI_STATUS_UP) ?
					    "up" : "down") == NULL)
			goto out;

		/* don't add interfaces unless there is at least one
		 * interface */
		if (strlen(ni_data->lic_ni_intf[0]) > 0) {
			interfaces = cYAML_create_object(item, "interfaces");
			if (interfaces == NULL)
				goto out;

			for (j = 0; j < LNET_NUM_INTERFACES; j++) {
				if (strlen(ni_data->lic_ni_intf[j]) > 0) {
					snprintf(str_buf,
						 sizeof(str_buf), "%d", j);
					if (cYAML_create_string(interfaces,
						str_buf,
						ni_data->lic_ni_intf[j]) ==
							NULL)
						goto out;
				}
			}
		}

		if (detail) {
			char *limit;

			statistics = cYAML_create_object(item, "statistics");
			if (statistics == NULL)
				goto out;

			if (cYAML_create_number(statistics, "send_count",
						stats->iel_send_count)
							== NULL)
				goto out;

			if (cYAML_create_number(statistics, "recv_count",
						stats->iel_recv_count)
							== NULL)
				goto out;

			if (cYAML_create_number(statistics, "drop_count",
						stats->iel_drop_count)
							== NULL)
				goto out;

			tunables = cYAML_create_object(item, "tunables");
			if (!tunables)
				goto out;

			rc = lustre_net_show_tunables(tunables, &lnd->lt_cmn);
			if (rc != LUSTRE_CFG_RC_NO_ERR)
				goto out;

			tunables = cYAML_create_object(item, "lnd tunables");
			if (tunables == NULL)
				goto out;

			rc = lustre_ni_show_tunables(tunables, LNET_NETTYP(rc_net),
						     &lnd->lt_tun);
			if (rc != LUSTRE_CFG_RC_NO_ERR)
				goto out;

			if (cYAML_create_number(item, "tcp bonding",
						ni_data->lic_tcp_bonding)
							== NULL)
				goto out;

			if (cYAML_create_number(item, "dev cpt",
						ni_data->lic_dev_cpt) == NULL)
				goto out;

			/* out put the CPTs in the format: "[x,x,x,...]" */
			limit = str_buf + str_buf_len - 3;
			pos += snprintf(pos, limit - pos, "\"[");
			for (j = 0 ; ni_data->lic_ncpts >= 1 &&
				j < ni_data->lic_ncpts &&
				pos < limit; j++) {
				pos += snprintf(pos, limit - pos,
						"%d", ni_data->lic_cpts[j]);
				if ((j + 1) < ni_data->lic_ncpts)
					pos += snprintf(pos, limit - pos, ",");
			}
			pos += snprintf(pos, 3, "]\"");

			if (ni_data->lic_ncpts >= 1 &&
			    cYAML_create_string(item, "CPT",
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

int lustre_lnet_config_numa_range(int range, int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_numa_range data;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"success\"");

	if (range < 0) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"range must be >= 0\"");
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	LIBCFS_IOC_INIT_V2(data, nr_hdr);
	data.nr_range = range;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_SET_NUMA_RANGE, &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot configure buffers: %s\"", strerror(errno));
		goto out;
	}

out:
	cYAML_build_error(rc, seq_no, ADD_CMD, "numa_range", err_str, err_rc);

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

int lustre_lnet_show_peer(char *knid, int detail, int seq_no,
			  struct cYAML **show_rc, struct cYAML **err_rc)
{
	/*
	 * TODO: This function is changing in a future patch to accommodate
	 * PEER_LIST and proper filtering on any nid of the peer
	 */
	struct lnet_ioctl_peer_cfg peer_info;
	struct lnet_peer_ni_credit_info *lpni_cri;
	struct lnet_ioctl_element_stats *lpni_stats;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM, ncpt = 0, i = 0, j = 0;
	int l_errno = 0;
	struct cYAML *root = NULL, *peer = NULL, *peer_ni = NULL,
		     *first_seq = NULL, *peer_root = NULL, *tmp = NULL;
	char err_str[LNET_MAX_STR_LEN];
	lnet_nid_t prev_primary_nid = LNET_NID_ANY, primary_nid = LNET_NID_ANY;
	int data_size = sizeof(*lpni_cri) + sizeof(*lpni_stats);
	char *data = malloc(data_size);
	bool new_peer = true;

	snprintf(err_str, sizeof(err_str),
		 "\"out of memory\"");

	if (data == NULL)
		goto out;

	/* create struct cYAML root object */
	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	peer_root = cYAML_create_seq(root, "peer");
	if (peer_root == NULL)
		goto out;

	if (knid != NULL)
		primary_nid = libcfs_str2nid(knid);

	do {
		for (i = 0;; i++) {
			memset(data, 0, data_size);
			memset(&peer_info, 0, sizeof(peer_info));
			LIBCFS_IOC_INIT_V2(peer_info, prcfg_hdr);
			peer_info.prcfg_hdr.ioc_len = sizeof(peer_info);
			peer_info.prcfg_count = i;
			peer_info.prcfg_bulk = (void *)data;
			peer_info.prcfg_size = data_size;

			rc = l_ioctl(LNET_DEV_ID,
				     IOC_LIBCFS_GET_PEER_NI, &peer_info);
			if (rc != 0) {
				l_errno = errno;
				break;
			}

			if (primary_nid != LNET_NID_ANY &&
			    primary_nid != peer_info.prcfg_prim_nid)
					continue;

			lpni_cri = peer_info.prcfg_bulk;
			lpni_stats = peer_info.prcfg_bulk + sizeof(*lpni_cri);

			peer = cYAML_create_seq_item(peer_root);
			if (peer == NULL)
				goto out;

			if (peer_info.prcfg_prim_nid != prev_primary_nid) {
				prev_primary_nid = peer_info.prcfg_prim_nid;
				new_peer = true;
			}

			if (new_peer) {
				lnet_nid_t pnid = peer_info.prcfg_prim_nid;
				if (cYAML_create_string(peer, "primary nid",
							libcfs_nid2str(pnid))
				    == NULL)
					goto out;
				if (cYAML_create_string(peer, "Multi-Rail",
							peer_info.prcfg_mr ?
							"True" : "False")
				    == NULL)
					goto out;
				tmp = cYAML_create_seq(peer, "peer ni");
				if (tmp == NULL)
					goto out;
				new_peer = false;
			}

			if (first_seq == NULL)
				first_seq = peer;

			peer_ni = cYAML_create_seq_item(tmp);
			if (peer_ni == NULL)
				goto out;

			if (cYAML_create_string(peer_ni, "nid",
						libcfs_nid2str
						 (peer_info.prcfg_cfg_nid))
			    == NULL)
				goto out;

			if (cYAML_create_string(peer_ni, "state",
						lpni_cri->cr_aliveness)
			    == NULL)
				goto out;

			if (!detail)
				continue;

			if (cYAML_create_number(peer_ni, "max_ni_tx_credits",
						lpni_cri->cr_ni_peer_tx_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "available_tx_credits",
						lpni_cri->cr_peer_tx_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "min_tx_credits",
						lpni_cri->cr_peer_min_tx_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "tx_q_num_of_buf",
						lpni_cri->cr_peer_tx_qnob)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "available_rtr_credits",
						lpni_cri->cr_peer_rtr_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "min_rtr_credits",
						lpni_cri->cr_peer_min_rtr_credits)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "send_count",
						lpni_stats->iel_send_count)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "recv_count",
						lpni_stats->iel_recv_count)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "drop_count",
						lpni_stats->iel_drop_count)
			    == NULL)
				goto out;

			if (cYAML_create_number(peer_ni, "refcount",
						lpni_cri->cr_refcount) == NULL)
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
						  "peer");
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

	cYAML_build_error(rc, seq_no, SHOW_CMD, "peer", err_str,
			  err_rc);

	return rc;
}

int lustre_lnet_show_numa_range(int seq_no, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	struct lnet_ioctl_numa_range data;
	int rc;
	int l_errno;
	char err_str[LNET_MAX_STR_LEN];
	struct cYAML *root = NULL, *range = NULL;

	snprintf(err_str, sizeof(err_str), "\"out of memory\"");

	LIBCFS_IOC_INIT_V2(data, nr_hdr);

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_NUMA_RANGE, &data);
	if (rc != 0) {
		l_errno = errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get numa range: %s\"",
			 strerror(l_errno));
		rc = -l_errno;
		goto out;
	}

	rc = LUSTRE_CFG_RC_OUT_OF_MEM;

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	range = cYAML_create_object(root, "numa");
	if (range == NULL)
		goto out;

	if (cYAML_create_number(range, "range",
				data.nr_range) == NULL)
		goto out;

	if (show_rc == NULL)
		cYAML_print_tree(root);

	snprintf(err_str, sizeof(err_str), "\"success\"");
	rc = LUSTRE_CFG_RC_NO_ERR;
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

	cYAML_build_error(rc, seq_no, SHOW_CMD, "numa", err_str, err_rc);

	return rc;
}

int lustre_lnet_show_stats(int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc)
{
	struct lnet_ioctl_lnet_stats data;
	int rc;
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

	rc = LUSTRE_CFG_RC_OUT_OF_MEM;

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
	rc = LUSTRE_CFG_RC_NO_ERR;
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

static void yaml_free_string_array(char **array, int num)
{
	int i;
	char **sub_array = array;

	for (i = 0; i < num; i++) {
		if (*sub_array != NULL)
			free(*sub_array);
		sub_array++;
	}
	if (array)
		free(array);
}

/*
 *    interfaces:
 *        0: <intf_name>['['<expr>']']
 *        1: <intf_name>['['<expr>']']
 */
static int yaml_copy_intf_info(struct cYAML *intf_tree,
			       struct lnet_dlc_network_descr *nw_descr)
{
	struct cYAML *child = NULL;
	int intf_num = 0, rc = LUSTRE_CFG_RC_NO_ERR;
	struct lnet_dlc_intf_descr *intf_descr, *tmp;

	if (intf_tree == NULL || nw_descr == NULL)
		return LUSTRE_CFG_RC_BAD_PARAM;

	/* now grab all the interfaces and their cpts */
	child = intf_tree->cy_child;
	while (child != NULL) {
		if (child->cy_valuestring == NULL) {
			child = child->cy_next;
			continue;
		}

		if (strlen(child->cy_valuestring) >= LNET_MAX_STR_LEN)
			goto failed;

		rc = lustre_lnet_add_intf_descr(&nw_descr->nw_intflist,
						child->cy_valuestring,
						strlen(child->cy_valuestring));
		if (rc != LUSTRE_CFG_RC_NO_ERR)
			goto failed;

		intf_num++;
		child = child->cy_next;
	}

	if (intf_num == 0)
		return LUSTRE_CFG_RC_MISSING_PARAM;

	return intf_num;

failed:
	list_for_each_entry_safe(intf_descr, tmp, &nw_descr->nw_intflist,
				 intf_on_network) {
		list_del(&intf_descr->intf_on_network);
		free_intf_descr(intf_descr);
	}

	return rc;
}

static bool
yaml_extract_cmn_tunables(struct cYAML *tree,
			  struct lnet_ioctl_config_lnd_cmn_tunables *tunables,
			  struct cfs_expr_list **global_cpts)
{
	struct cYAML *tun, *item, *smp;
	int rc;

	tun = cYAML_get_object_item(tree, "tunables");
	if (tun != NULL) {
		item = cYAML_get_object_item(tun, "peer_timeout");
		if (item != NULL)
			tunables->lct_peer_timeout = item->cy_valueint;
		item = cYAML_get_object_item(tun, "peer_credits");
		if (item != NULL)
			tunables->lct_peer_tx_credits = item->cy_valueint;
		item = cYAML_get_object_item(tun, "peer_buffer_credits");
		if (item != NULL)
			tunables->lct_peer_rtr_credits = item->cy_valueint;
		item = cYAML_get_object_item(tun, "credits");
		if (item != NULL)
			tunables->lct_max_tx_credits = item->cy_valueint;
		smp = cYAML_get_object_item(tun, "CPT");
		if (smp != NULL) {
			rc = cfs_expr_list_parse(smp->cy_valuestring,
						 strlen(smp->cy_valuestring),
						 0, UINT_MAX, global_cpts);
			if (rc != 0)
				*global_cpts = NULL;
		}

		return true;
	}

	return false;
}

static bool
yaml_extract_tunables(struct cYAML *tree,
		      struct lnet_ioctl_config_lnd_tunables *tunables,
		      struct cfs_expr_list **global_cpts,
		      __u32 net_type)
{
	bool rc;

	rc = yaml_extract_cmn_tunables(tree, &tunables->lt_cmn,
				       global_cpts);

	if (!rc)
		return rc;

	lustre_yaml_extract_lnd_tunables(tree, net_type,
					 &tunables->lt_tun);

	return rc;
}

/*
 * net:
 *    - net type: <net>[<NUM>]
  *      local NI(s):
 *        - nid: <ip>@<net>[<NUM>]
 *          status: up
 *          interfaces:
 *               0: <intf_name>['['<expr>']']
 *               1: <intf_name>['['<expr>']']
 *        tunables:
 *               peer_timeout: <NUM>
 *               peer_credits: <NUM>
 *               peer_buffer_credits: <NUM>
 *               credits: <NUM>
*         lnd tunables:
 *               peercredits_hiw: <NUM>
 *               map_on_demand: <NUM>
 *               concurrent_sends: <NUM>
 *               fmr_pool_size: <NUM>
 *               fmr_flush_trigger: <NUM>
 *               fmr_cache: <NUM>
 *
 * At least one interface is required. If no interfaces are provided the
 * network interface can not be configured.
 */
static int handle_yaml_config_ni(struct cYAML *tree, struct cYAML **show_rc,
				 struct cYAML **err_rc)
{
	struct cYAML *net, *intf, *seq_no, *ip2net = NULL, *local_nis = NULL,
		     *item = NULL;
	int num_entries = 0, rc;
	struct lnet_dlc_network_descr nw_descr;
	struct cfs_expr_list *global_cpts = NULL;
	struct lnet_ioctl_config_lnd_tunables tunables;
	bool found = false;

	memset(&tunables, 0, sizeof(tunables));

	INIT_LIST_HEAD(&nw_descr.network_on_rule);
	INIT_LIST_HEAD(&nw_descr.nw_intflist);

	ip2net = cYAML_get_object_item(tree, "ip2net");
	net = cYAML_get_object_item(tree, "net type");
	if (net)
		nw_descr.nw_id = libcfs_str2net(net->cy_valuestring);
	else
		nw_descr.nw_id = LOLND;

	/*
	 * if neither net nor ip2nets are present, then we can not
	 * configure the network.
	 */
	if (!net && !ip2net)
		return LUSTRE_CFG_RC_MISSING_PARAM;

	local_nis = cYAML_get_object_item(tree, "local NI(s)");
	if (local_nis == NULL)
		return LUSTRE_CFG_RC_MISSING_PARAM;

	if (!cYAML_is_sequence(local_nis))
		return LUSTRE_CFG_RC_BAD_PARAM;

	while (cYAML_get_next_seq_item(local_nis, &item) != NULL) {
		intf = cYAML_get_object_item(item, "interfaces");
		if (intf == NULL)
			continue;
		num_entries = yaml_copy_intf_info(intf, &nw_descr);
		if (num_entries <= 0) {
			cYAML_build_error(num_entries, -1, "ni", "add",
					"bad interface list",
					err_rc);
			return LUSTRE_CFG_RC_BAD_PARAM;
		}
	}

	found = yaml_extract_tunables(tree, &tunables, &global_cpts,
				      LNET_NETTYP(nw_descr.nw_id));
	seq_no = cYAML_get_object_item(tree, "seq_no");

	rc = lustre_lnet_config_ni(&nw_descr,
				   global_cpts,
				   (ip2net) ? ip2net->cy_valuestring : NULL,
				   (found) ? &tunables: NULL,
				   (seq_no) ? seq_no->cy_valueint : -1,
				   err_rc);

	if (global_cpts != NULL)
		cfs_expr_list_free(global_cpts);

	return rc;
}

/*
 * ip2nets:
 *  - net-spec: <tcp|o2ib|gni>[NUM]
 *    interfaces:
 *        0: <intf name>['['<expr>']']
 *        1: <intf name>['['<expr>']']
 *    ip-range:
 *        0: <expr.expr.expr.expr>
 *        1: <expr.expr.expr.expr>
 */
static int handle_yaml_config_ip2nets(struct cYAML *tree,
				      struct cYAML **show_rc,
				      struct cYAML **err_rc)
{
	struct cYAML *net, *ip_range, *item = NULL, *intf = NULL,
		     *seq_no = NULL;
	struct lustre_lnet_ip2nets ip2nets;
	struct lustre_lnet_ip_range_descr *ip_range_descr = NULL,
					  *tmp = NULL;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	struct cfs_expr_list *global_cpts = NULL;
	struct cfs_expr_list *el, *el_tmp;
	struct lnet_ioctl_config_lnd_tunables tunables;
	struct lnet_dlc_intf_descr *intf_descr, *intf_tmp;
	bool found = false;

	memset(&tunables, 0, sizeof(tunables));

	/* initialize all lists */
	INIT_LIST_HEAD(&ip2nets.ip2nets_ip_ranges);
	INIT_LIST_HEAD(&ip2nets.ip2nets_net.network_on_rule);
	INIT_LIST_HEAD(&ip2nets.ip2nets_net.nw_intflist);

	net = cYAML_get_object_item(tree, "net-spec");
	if (net == NULL)
		return LUSTRE_CFG_RC_BAD_PARAM;

	if (net != NULL && net->cy_valuestring == NULL)
		return LUSTRE_CFG_RC_BAD_PARAM;

	/* assign the network id */
	ip2nets.ip2nets_net.nw_id = libcfs_str2net(net->cy_valuestring);
	if (ip2nets.ip2nets_net.nw_id == LNET_NID_ANY)
		return LUSTRE_CFG_RC_BAD_PARAM;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	intf = cYAML_get_object_item(tree, "interfaces");
	if (intf != NULL) {
		rc = yaml_copy_intf_info(intf, &ip2nets.ip2nets_net);
		if (rc <= 0)
			return LUSTRE_CFG_RC_BAD_PARAM;
	}

	ip_range = cYAML_get_object_item(tree, "ip-range");
	if (ip_range != NULL) {
		item = ip_range->cy_child;
		while (item != NULL) {
			if (item->cy_valuestring == NULL) {
				item = item->cy_next;
				continue;
			}

			rc = lustre_lnet_add_ip_range(&ip2nets.ip2nets_ip_ranges,
						      item->cy_valuestring);

			if (rc != LUSTRE_CFG_RC_NO_ERR)
				goto out;

			item = item->cy_next;
		}
	}

	found = yaml_extract_tunables(tree, &tunables, &global_cpts,
				      LNET_NETTYP(ip2nets.ip2nets_net.nw_id));

	rc = lustre_lnet_config_ip2nets(&ip2nets,
			(found) ? &tunables : NULL,
			global_cpts,
			(seq_no) ? seq_no->cy_valueint : -1,
			err_rc);

	/*
	 * don't stop because there was no match. Continue processing the
	 * rest of the rules. If non-match then nothing is configured
	 */
	if (rc == LUSTRE_CFG_RC_NO_MATCH)
		rc = LUSTRE_CFG_RC_NO_ERR;
out:
	list_for_each_entry_safe(intf_descr, intf_tmp,
				 &ip2nets.ip2nets_net.nw_intflist,
				 intf_on_network) {
		list_del(&intf_descr->intf_on_network);
		free_intf_descr(intf_descr);
	}

	list_for_each_entry_safe(ip_range_descr, tmp,
				 &ip2nets.ip2nets_ip_ranges,
				 ipr_entry) {
		list_del(&ip_range_descr->ipr_entry);
		list_for_each_entry_safe(el, el_tmp, &ip_range_descr->ipr_expr,
					 el_link) {
			list_del(&el->el_link);
			cfs_expr_list_free(el);
		}
		free(ip_range_descr);
	}

	return rc;
}

static int handle_yaml_del_ni(struct cYAML *tree, struct cYAML **show_rc,
			      struct cYAML **err_rc)
{
	struct cYAML *net = NULL, *intf = NULL, *seq_no = NULL, *item = NULL,
		     *local_nis = NULL;
	int num_entries, rc;
	struct lnet_dlc_network_descr nw_descr;

	INIT_LIST_HEAD(&nw_descr.network_on_rule);
	INIT_LIST_HEAD(&nw_descr.nw_intflist);

	net = cYAML_get_object_item(tree, "net type");
	if (net != NULL)
		nw_descr.nw_id = libcfs_str2net(net->cy_valuestring);

	local_nis = cYAML_get_object_item(tree, "local NI(s)");
	if (local_nis == NULL)
		return LUSTRE_CFG_RC_MISSING_PARAM;

	if (!cYAML_is_sequence(local_nis))
		return LUSTRE_CFG_RC_BAD_PARAM;

	while (cYAML_get_next_seq_item(local_nis, &item) != NULL) {
		intf = cYAML_get_object_item(item, "interfaces");
		if (intf == NULL)
			continue;
		num_entries = yaml_copy_intf_info(intf, &nw_descr);
		if (num_entries <= 0) {
			cYAML_build_error(num_entries, -1, "ni", "add",
					"bad interface list",
					err_rc);
			return LUSTRE_CFG_RC_BAD_PARAM;
		}
	}

	seq_no = cYAML_get_object_item(tree, "seq_no");

	rc = lustre_lnet_del_ni((net) ? &nw_descr : NULL,
				(seq_no) ? seq_no->cy_valueint : -1,
				err_rc);

	return rc;
}

static int yaml_copy_peer_nids(struct cYAML *tree, char ***nidsppp, bool del)
{
	struct cYAML *nids_entry = NULL, *child = NULL, *entry = NULL,
		     *prim_nid = NULL;
	char **nids = NULL;
	int num = 0, rc = LUSTRE_CFG_RC_NO_ERR;

	prim_nid = cYAML_get_object_item(tree, "primary nid");
	if (!prim_nid || !prim_nid->cy_valuestring)
		return LUSTRE_CFG_RC_MISSING_PARAM;

	nids_entry = cYAML_get_object_item(tree, "peer ni");
	if (cYAML_is_sequence(nids_entry)) {
		while (cYAML_get_next_seq_item(nids_entry, &child)) {
			entry = cYAML_get_object_item(child, "nid");
			/* don't count an empty entry */
			if (!entry || !entry->cy_valuestring)
				continue;

			if ((strcmp(entry->cy_valuestring, prim_nid->cy_valuestring)
					== 0) && del) {
				/*
				 * primary nid is present in the list of
				 * nids so that means we want to delete
				 * the entire peer, so no need to go
				 * further. Just delete the entire peer.
				 */
				return 0;
			}

			num++;
		}
	}

	if (num == 0)
		return LUSTRE_CFG_RC_MISSING_PARAM;

	nids = calloc(sizeof(*nids) * num, 1);
	if (nids == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	/* now grab all the nids */
	num = 0;
	child = NULL;
	while (cYAML_get_next_seq_item(nids_entry, &child)) {
		entry = cYAML_get_object_item(child, "nid");
		if (!entry || !entry->cy_valuestring)
			continue;

		nids[num] = calloc(strlen(entry->cy_valuestring) + 1, 1);
		if (!nids[num]) {
			rc = LUSTRE_CFG_RC_OUT_OF_MEM;
			goto failed;
		}
		strncpy(nids[num], entry->cy_valuestring,
			strlen(entry->cy_valuestring));
		num++;
	}
	rc = num;

	*nidsppp = nids;
	return rc;

failed:
	if (nids != NULL)
		yaml_free_string_array(nids, num);
	*nidsppp = NULL;
	return rc;
}

static int handle_yaml_config_peer(struct cYAML *tree, struct cYAML **show_rc,
				   struct cYAML **err_rc)
{
	char **nids = NULL;
	int num, rc;
	struct cYAML *seq_no, *prim_nid, *non_mr;

	num = yaml_copy_peer_nids(tree, &nids, false);
	if (num < 0)
		return num;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	prim_nid = cYAML_get_object_item(tree, "primary nid");
	non_mr = cYAML_get_object_item(tree, "non_mr");

	rc = lustre_lnet_config_peer_nid((prim_nid) ? prim_nid->cy_valuestring : NULL,
					 nids, num,
					 (non_mr) ? false : true,
					 (seq_no) ? seq_no->cy_valueint : -1,
					 err_rc);

	yaml_free_string_array(nids, num);
	return rc;
}

static int handle_yaml_del_peer(struct cYAML *tree, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	char **nids = NULL;
	int num, rc;
	struct cYAML *seq_no, *prim_nid;

	num = yaml_copy_peer_nids(tree, &nids, true);
	if (num < 0)
		return num;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	prim_nid = cYAML_get_object_item(tree, "primary nid");

	rc = lustre_lnet_del_peer_nid((prim_nid) ? prim_nid->cy_valuestring : NULL,
				      nids, num,
				      (seq_no) ? seq_no->cy_valueint : -1,
				      err_rc);

	yaml_free_string_array(nids, num);
	return rc;
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

static int handle_yaml_show_peers(struct cYAML *tree, struct cYAML **show_rc,
				  struct cYAML **err_rc)
{
	struct cYAML *seq_no, *nid, *detail;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	detail = cYAML_get_object_item(tree, "detail");
	nid = cYAML_get_object_item(tree, "nid");

	return lustre_lnet_show_peer((nid) ? nid->cy_valuestring : NULL,
				     (detail) ? detail->cy_valueint : 0,
				     (seq_no) ? seq_no->cy_valueint : -1,
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

static int handle_yaml_config_numa(struct cYAML *tree, struct cYAML **show_rc,
				  struct cYAML **err_rc)
{
	struct cYAML *seq_no, *range;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	range = cYAML_get_object_item(tree, "range");

	return lustre_lnet_config_numa_range(range ? range->cy_valueint : -1,
					     seq_no ? seq_no->cy_valueint : -1,
					     err_rc);
}

static int handle_yaml_del_numa(struct cYAML *tree, struct cYAML **show_rc,
			       struct cYAML **err_rc)
{
	struct cYAML *seq_no;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_config_numa_range(0, seq_no ? seq_no->cy_valueint : -1,
					     err_rc);
}

static int handle_yaml_show_numa(struct cYAML *tree, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	struct cYAML *seq_no;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_show_numa_range(seq_no ? seq_no->cy_valueint : -1,
					   show_rc, err_rc);
}

struct lookup_cmd_hdlr_tbl {
	char *name;
	cmd_handler_t cb;
};

static struct lookup_cmd_hdlr_tbl lookup_config_tbl[] = {
	{ .name = "route",	.cb = handle_yaml_config_route },
	{ .name = "net",	.cb = handle_yaml_config_ni },
	{ .name = "ip2nets",	.cb = handle_yaml_config_ip2nets },
	{ .name = "peer",	.cb = handle_yaml_config_peer },
	{ .name = "routing",	.cb = handle_yaml_config_routing },
	{ .name = "buffers",	.cb = handle_yaml_config_buffers },
	{ .name = "numa",	.cb = handle_yaml_config_numa },
	{ .name = NULL } };

static struct lookup_cmd_hdlr_tbl lookup_del_tbl[] = {
	{ .name = "route",	.cb = handle_yaml_del_route },
	{ .name = "net",	.cb = handle_yaml_del_ni },
	{ .name = "peer",	.cb = handle_yaml_del_peer },
	{ .name = "routing",	.cb = handle_yaml_del_routing },
	{ .name = "numa",	.cb = handle_yaml_del_numa },
	{ .name = NULL } };

static struct lookup_cmd_hdlr_tbl lookup_show_tbl[] = {
	{ .name = "route",	.cb = handle_yaml_show_route },
	{ .name = "net",	.cb = handle_yaml_show_net },
	{ .name = "buffers",	.cb = handle_yaml_show_routing },
	{ .name = "routing",	.cb = handle_yaml_show_routing },
	{ .name = "peer",	.cb = handle_yaml_show_peers },
	{ .name = "statistics",	.cb = handle_yaml_show_stats },
	{ .name = "numa",	.cb = handle_yaml_show_numa },
	{ .name = NULL } };

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

	tree = cYAML_build_tree(f, NULL, 0, err_rc, false);
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

