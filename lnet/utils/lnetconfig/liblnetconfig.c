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
#include <linux/lnet/lnetctl.h>
#include "liblnd.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <rdma/rdma_user_cm.h>
#include "liblnetconfig.h"
#include <glob.h>
#include <libcfs/util/param.h>

#ifndef HAVE_USRSPC_RDMA_PS_TCP
#define RDMA_PS_TCP 0x0106
#endif

const char *gmsg_stat_names[] = {"sent_stats", "received_stats",
				 "dropped_stats"};

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

int open_sysfs_file(const char *path, const char *attr, const int mode)
{
	int fd;
	char filename[LNET_MAX_STR_LEN];

	if (strlen(path) + strlen(attr) >= LNET_MAX_STR_LEN)
		return -1;

	snprintf(filename, sizeof(filename), "%s%s",
		 path, attr);

	fd = open(filename, mode);

	return fd;
}

static int read_sysfs_file(const char *path, const char *attr,
			   void *val, const size_t size, const int nelem)
{
	int fd;
	int rc = LUSTRE_CFG_RC_GENERIC_ERR;

	fd = open_sysfs_file(path, attr, O_RDONLY);
	if (fd == -1)
		return LUSTRE_CFG_RC_NO_MATCH;

	if (read(fd, val, size * nelem) == -1)
		goto close_fd;

	rc = LUSTRE_CFG_RC_NO_ERR;

close_fd:
	close(fd);
	return rc;
}

static int write_sysfs_file(const char *path, const char *attr,
			    void *val, const size_t size, const int nelem)
{
	int fd;
	int rc = LUSTRE_CFG_RC_GENERIC_ERR;

	fd = open_sysfs_file(path, attr, O_WRONLY | O_TRUNC);
	if (fd == -1)
		return LUSTRE_CFG_RC_NO_MATCH;

	if (write(fd, val, size * nelem) == -1)
		goto close_fd;

	rc = LUSTRE_CFG_RC_NO_ERR;

close_fd:
	close(fd);
	return rc;
}

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
		nw_descr->nw_id = 0;
		INIT_LIST_HEAD(&nw_descr->network_on_rule);
		INIT_LIST_HEAD(&nw_descr->nw_intflist);
	}
}

int lustre_lnet_parse_nidstr(char *nidstr, lnet_nid_t *lnet_nidlist,
			     int max_nids, char *err_str)
{
	int rc, num_nids = 0;
	struct list_head nidlist;

	if (!nidstr) {
		snprintf(err_str, LNET_MAX_STR_LEN, "supplied nidstr is NULL");
		return LUSTRE_CFG_RC_BAD_PARAM;
	}

	if (strchr(nidstr, '*')) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "asterisk not allowed in nidstring \"%s\"", nidstr);
		return LUSTRE_CFG_RC_BAD_PARAM;
	}

	INIT_LIST_HEAD(&nidlist);
	rc = cfs_parse_nidlist(nidstr, strlen(nidstr), &nidlist);
	if (rc == 0) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "Unable to parse nidlist from: %s\n", nidstr);
		return LUSTRE_CFG_RC_BAD_PARAM;
	}

	if (list_empty(&nidlist)) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"%s\" does not specify any valid nid lists", nidstr);
		return LUSTRE_CFG_RC_BAD_PARAM;
	}

	num_nids = cfs_expand_nidlist(&nidlist, lnet_nidlist, max_nids);
	cfs_free_nidlist(&nidlist);

	if (num_nids == -1) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"%s\" specifies more than the %d NIDs allowed by this operation.",
			 nidstr, max_nids);
		return LUSTRE_CFG_RC_BAD_PARAM;
	}

	if (num_nids < 0) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "Failed to expand nidstr: %s", strerror(num_nids));
		return LUSTRE_CFG_RC_OUT_OF_MEM;
	}

	if (num_nids == 0) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"%s\" did not expand to any nids", nidstr);
		return LUSTRE_CFG_RC_BAD_PARAM;
	}

	return num_nids;
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
	char err_str[LNET_MAX_STR_LEN] = "\"Success\"";

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

static int dispatch_peer_ni_cmd(__u32 cmd, struct lnet_ioctl_peer_cfg *data,
				char *err_str, char *cmd_str)
{
	int rc;

	rc = l_ioctl(LNET_DEV_ID, cmd, data);
	if (rc) {
		rc = -errno;
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"%s peer ni operation failed: %s\"",
			 cmd_str, strerror(errno));
	}

	return rc;
}

static int infra_ping_nid(char *ping_nids, char *oper, int param, int ioc_call,
			  int seq_no, struct cYAML **show_rc,
			  struct cYAML **err_rc)
{
	void *data = NULL;
	struct lnet_ioctl_ping_data ping;
	struct cYAML *root = NULL, *ping_node = NULL, *item = NULL,
		     *first_seq = NULL,	*tmp = NULL, *peer_ni = NULL;
	struct lnet_process_id id;
	char err_str[LNET_MAX_STR_LEN] = {0};
	char *sep, *token, *end;
	char buf[6];
	size_t len;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	int i;
	bool flag = false;

	len = (sizeof(struct lnet_process_id) * LNET_INTERFACES_MAX_DEFAULT);

	data = calloc(1, len);
	if (data == NULL)
		goto out;

	/* create struct cYAML root object */
	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	ping_node = cYAML_create_seq(root, oper);
	if (ping_node == NULL)
		goto out;

	/* tokenise each nid in string ping_nids */
	token = strtok(ping_nids, ",");

	do {
		item = cYAML_create_seq_item(ping_node);
		if (item == NULL)
			goto out;

		if (first_seq == NULL)
			first_seq = item;

		/* check if '-' is a part of NID, token */
		sep = strchr(token, '-');
		if (sep == NULL) {
			id.pid = LNET_PID_ANY;
			/* if no net is specified, libcfs_str2nid() will assume tcp */
			id.nid = libcfs_str2nid(token);
			if (id.nid == LNET_NID_ANY) {
				snprintf(err_str, sizeof(err_str),
					 "\"cannot parse NID '%s'\"",
					 token);
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				cYAML_build_error(rc, seq_no, MANAGE_CMD,
						  oper, err_str, err_rc);
				continue;
			}
		} else {
			if (token[0] == 'u' || token[0] == 'U')
				id.pid = (strtoul(&token[1], &end, 0) |
					  (LNET_PID_USERFLAG));
			else
				id.pid = strtoul(token, &end, 0);

			/* assuming '-' is part of hostname */
			if (end != sep) {
				id.pid = LNET_PID_ANY;
				id.nid = libcfs_str2nid(token);
				if (id.nid == LNET_NID_ANY) {
					snprintf(err_str, sizeof(err_str),
						 "\"cannot parse NID '%s'\"",
						 token);
					rc = LUSTRE_CFG_RC_BAD_PARAM;
					cYAML_build_error(rc, seq_no, MANAGE_CMD,
							  oper, err_str,
							  err_rc);
					continue;
				}
			} else {
				id.nid = libcfs_str2nid(sep + 1);
				if (id.nid == LNET_NID_ANY) {
					snprintf(err_str, sizeof(err_str),
						 "\"cannot parse NID '%s'\"",
						 token);
					rc = LUSTRE_CFG_RC_BAD_PARAM;
					cYAML_build_error(rc, seq_no, MANAGE_CMD,
							  oper, err_str,
							  err_rc);
					continue;
				}
			}
		}
		LIBCFS_IOC_INIT_V2(ping, ping_hdr);
		ping.ping_hdr.ioc_len = sizeof(ping);
		ping.ping_id          = id;
		ping.op_param         = param;
		ping.ping_count       = LNET_INTERFACES_MAX_DEFAULT;
		ping.ping_buf         = data;

		rc = l_ioctl(LNET_DEV_ID, ioc_call, &ping);
		if (rc != 0) {
			snprintf(err_str,
				 sizeof(err_str), "failed to %s %s: %s\n", oper,
				 id.pid == LNET_PID_ANY ?
				 libcfs_nid2str(id.nid) :
				 libcfs_id2str(id), strerror(errno));
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			cYAML_build_error(rc, seq_no, MANAGE_CMD,
					  oper, err_str, err_rc);
			continue;
		}

		if (cYAML_create_string(item, "primary nid",
					libcfs_nid2str(ping.ping_id.nid)) == NULL)
			goto out;

		if (cYAML_create_string(item, "Multi-Rail", ping.mr_info ?
					"True" : "False") == NULL)
			goto out;

		tmp = cYAML_create_seq(item, "peer ni");
		if (tmp == NULL)
			goto out;

		for (i = 0; i < ping.ping_count; i++) {
			if (ping.ping_buf[i].nid == LNET_NID_LO_0)
				continue;
			peer_ni = cYAML_create_seq_item(tmp);
			if (peer_ni == NULL)
				goto out;
			memset(buf, 0, sizeof buf);
			snprintf(buf, sizeof buf, "nid");
			if (cYAML_create_string(peer_ni, buf,
						libcfs_nid2str(ping.ping_buf[i].nid)) == NULL)
				goto out;
		}

		flag = true;

	} while ((token = strtok(NULL, ",")) != NULL);

	if (flag)
		rc = LUSTRE_CFG_RC_NO_ERR;

out:
	if (data)
		free(data);
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		struct cYAML *show_node;
		show_node = cYAML_get_object_item(*show_rc, oper);
		if (show_node != NULL && cYAML_is_sequence(show_node)) {
			cYAML_insert_child(show_node, first_seq);
			free(ping_node);
			free(root);
		} else if (show_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
					     ping_node);
			free(root);
		} else {
			cYAML_free_tree(root);
		}
	} else {
		*show_rc = root;
	}

	return rc;
}

int lustre_lnet_ping_nid(char *ping_nids, int timeout, int seq_no,
			 struct cYAML **show_rc, struct cYAML **err_rc)
{
	int rc;

	rc = infra_ping_nid(ping_nids, "ping", timeout, IOC_LIBCFS_PING_PEER,
			    seq_no, show_rc, err_rc);
	return rc;
}

int lustre_lnet_discover_nid(char *ping_nids, int force, int seq_no,
			 struct cYAML **show_rc, struct cYAML **err_rc)
{
	int rc;

	rc = infra_ping_nid(ping_nids, "discover", force, IOC_LIBCFS_DISCOVER,
			    seq_no, show_rc, err_rc);
	return rc;
}

static int lustre_lnet_handle_peer_nidlist(lnet_nid_t *nidlist, int num_nids,
					   bool is_mr, __u32 cmd,
					   char *cmd_type, char *err_str)
{
	struct lnet_ioctl_peer_cfg data;
	int rc, nid_idx;

	if (cmd == IOC_LIBCFS_ADD_PEER_NI) {
		/* When adding a peer we first need to create the peer using the
		 * specified (or implied) primary nid. Then we can add
		 * additional nids to this peer using the primary nid as a key
		 */
		LIBCFS_IOC_INIT_V2(data, prcfg_hdr);
		data.prcfg_mr = is_mr;
		data.prcfg_prim_nid = nidlist[0];
		data.prcfg_cfg_nid = LNET_NID_ANY;

		rc = dispatch_peer_ni_cmd(cmd, &data, err_str, cmd_type);

		if (rc)
			return rc;
	}

	/* Add or delete any specified NIs associated with the specified
	 * (or implied) primary nid
	 */
	for (nid_idx = 1; nid_idx < num_nids; nid_idx++) {
		LIBCFS_IOC_INIT_V2(data, prcfg_hdr);
		data.prcfg_mr = is_mr;
		data.prcfg_prim_nid = nidlist[0];
		data.prcfg_cfg_nid = nidlist[nid_idx];

		rc = dispatch_peer_ni_cmd(cmd, &data, err_str, cmd_type);

		if (rc)
			return rc;
	}

	if (cmd == IOC_LIBCFS_DEL_PEER_NI && num_nids == 1) {
		/* In the delete case we may have been given just the
		 * primary nid of the peer. This tells us to delete the peer
		 * completely (rather than just delete some of its NIs)
		 */
		LIBCFS_IOC_INIT_V2(data, prcfg_hdr);
		data.prcfg_prim_nid = nidlist[0];
		data.prcfg_cfg_nid = LNET_NID_ANY;

		rc = dispatch_peer_ni_cmd(cmd, &data, err_str, cmd_type);
	}

	return rc;
}

static int
lustre_lnet_mod_peer_nidlist(lnet_nid_t pnid, lnet_nid_t *lnet_nidlist,
			     int cmd, int num_nids, bool is_mr, int seq_no,
			     struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];
	lnet_nid_t *lnet_nidlist2 = NULL;
	int ioc_cmd = (cmd == LNETCTL_ADD_CMD) ? IOC_LIBCFS_ADD_PEER_NI :
		IOC_LIBCFS_DEL_PEER_NI;
	char *cmd_str = (cmd == LNETCTL_ADD_CMD) ? ADD_CMD : DEL_CMD;

	num_nids++;
	lnet_nidlist2 = calloc(sizeof(*lnet_nidlist2), num_nids);
	if (!lnet_nidlist2) {
		snprintf(err_str, LNET_MAX_STR_LEN, "out of memory");
		rc = LUSTRE_CFG_RC_OUT_OF_MEM;
		goto out;
	}
	lnet_nidlist2[0] = pnid;
	memcpy(&lnet_nidlist2[1], lnet_nidlist, sizeof(*lnet_nidlist) *
						(num_nids - 1));

	rc = lustre_lnet_handle_peer_nidlist(lnet_nidlist2,
					     num_nids, is_mr, ioc_cmd,
					     cmd_str, err_str);
out:
	if (lnet_nidlist2)
		free(lnet_nidlist2);

	cYAML_build_error(rc, seq_no, cmd_str, "peer_ni", err_str, err_rc);
	return rc;
}

static void
replace_sep(char *str, char sep, char newsep)
{
	int bracket = 0;
	int i;
	if (!str)
		return;
	for (i = 0; i < strlen(str); i++) {
		/* don't replace ',' within [] */
		if (str[i] == '[')
			bracket++;
		else if (str[i] == ']')
			bracket--;
		else if (str[i] == sep && bracket == 0)
			str[i] = newsep;
	}
}

int lustre_lnet_modify_peer(char *prim_nid, char *nids, bool is_mr,
			    int cmd, int seq_no, struct cYAML **err_rc)
{
	int num_nids, rc;
	char err_str[LNET_MAX_STR_LEN] = "Error";
	lnet_nid_t lnet_nidlist[LNET_MAX_NIDS_PER_PEER];
	lnet_nid_t pnid = LNET_NID_ANY;

	if (!prim_nid) {
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "--prim_nid must be specified");
		goto out;
	}

	pnid = libcfs_str2nid(prim_nid);
	if (pnid == LNET_NID_ANY) {
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		snprintf(err_str, LNET_MAX_STR_LEN,
			"badly formatted primary NID: %s", prim_nid);
		goto out;
	}

	num_nids = 0;
	if (nids) {
		/*
		* if there is no primary nid we need to make the first nid in the
		* nids list the primary nid
		*/
		replace_sep(nids, ',', ' ');
		rc = lustre_lnet_parse_nidstr(nids, lnet_nidlist,
					LNET_MAX_NIDS_PER_PEER, err_str);
		if (rc < 0)
			goto out;

		num_nids = rc;
	}

	rc = lustre_lnet_mod_peer_nidlist(pnid, lnet_nidlist,
					  cmd, num_nids, is_mr,
					  -1, err_rc);

out:
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_build_error(rc, -1, "peer",
				cmd == LNETCTL_ADD_CMD ? "add" : "del",
				err_str, err_rc);

	return rc;
}

int lustre_lnet_route_common(char *nw, char *nidstr, int hops, int prio,
			     int sen, int seq_no, struct cYAML **err_rc,
			     int cmd)
{
	int rc, num_nids, idx;
	__u32 rnet;
	char err_str[LNET_MAX_STR_LEN] = "\"generic error\"";
	struct lnet_ioctl_config_data data;
	lnet_nid_t lnet_nidlist[LNET_MAX_NIDS_PER_PEER];

	if (nw == NULL || nidstr == NULL) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"missing mandatory parameter:'%s'\"",
			 (nw == NULL && nidstr == NULL) ? "network, gateway" :
			 (nw == NULL) ? "network" : "gateway");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	}

	rnet = libcfs_str2net(nw);
	if (rnet == LNET_NET_ANY) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"cannot parse remote net %s\"", nw);
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	replace_sep(nidstr, ',', ' ');
	rc = lustre_lnet_parse_nidstr(nidstr, lnet_nidlist,
				      LNET_MAX_NIDS_PER_PEER, err_str);
	if (rc < 0)
		goto out;

	num_nids = rc;

	for (idx = 0; idx < num_nids; idx++) {
		LIBCFS_IOC_INIT_V2(data, cfg_hdr);
		data.cfg_net = rnet;
		if (cmd == LNETCTL_ADD_CMD) {
			data.cfg_config_u.cfg_route.rtr_hop = hops;
			data.cfg_config_u.cfg_route.rtr_priority = prio;
			data.cfg_config_u.cfg_route.rtr_sensitivity = sen;
		}

		data.cfg_nid = lnet_nidlist[idx];

		if (cmd == LNETCTL_ADD_CMD)
			rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_ROUTE,
					&data);
		else
			rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_ROUTE,
					&data);

		if (rc != 0 && errno != EEXIST &&
			errno != EHOSTUNREACH) {
			rc = -errno;
			snprintf(err_str, LNET_MAX_STR_LEN,
					"route operation failed: %s",
					strerror(errno));
			goto out;
		} else if (errno == EEXIST) {
			/*
			 * continue chugging along if one of the
			 * routes already exists
			 */
			rc = 0;
		}
	}

out:
	cYAML_build_error(rc, seq_no,
			  cmd == LNETCTL_ADD_CMD ? ADD_CMD : DEL_CMD, "route",
			  err_str, err_rc);

	return rc;
}

int lustre_lnet_config_route(char *nw, char *nidstr, int hops, int prio,
			     int sen, int seq_no, struct cYAML **err_rc)
{
	int rc;
	char err_str[LNET_MAX_STR_LEN] = "\"generic error\"";

	if (hops == -1) {
		hops = LNET_UNDEFINED_HOPS;
	} else if (hops < 1 || hops > 255) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"invalid hop count %d, must be between 1 and 255\"",
			 hops);
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	if (prio == -1) {
		prio = 0;
	} else if (prio < 0) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"invalid priority %d, must be greater than 0\"",
			 prio);
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	if (sen == -1) {
		sen = 1;
	} else if (sen < 1) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"invalid health sensitivity %d, must be 1 or greater\"",
			 sen);
		rc = LUSTRE_CFG_RC_OUT_OF_RANGE_PARAM;
		goto out;
	}

	rc = lustre_lnet_route_common(nw, nidstr, hops, prio, sen, seq_no,
				      err_rc, LNETCTL_ADD_CMD);
	return rc;
out:
	cYAML_build_error(rc, seq_no, ADD_CMD, "route", err_str, err_rc);

	return rc;
}

int lustre_lnet_del_route(char *nw, char *nidstr, int seq_no,
			  struct cYAML **err_rc)
{
	return lustre_lnet_route_common(nw, nidstr, 0, 0, 0, seq_no, err_rc,
					LNETCTL_DEL_CMD);
}

int lustre_lnet_show_route(char *nw, char *gw, int hops, int prio, int detail,
			   int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc, bool backup)
{
	struct lnet_ioctl_config_data data;
	lnet_nid_t gateway_nid;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	int l_errno = 0;
	__u32 net = LNET_NET_ANY;
	int i;
	struct cYAML *root = NULL, *route = NULL, *item = NULL;
	struct cYAML *first_seq = NULL;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";
	bool exist = false;

	if (nw != NULL) {
		net = libcfs_str2net(nw);
		if (net == LNET_NET_ANY) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\"cannot parse net '%s'\"", nw);
			rc = LUSTRE_CFG_RC_BAD_PARAM;
			goto out;
		}

	} else {
		/* show all routes without filtering on net */
		net = LNET_NET_ANY;
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
		__u32 rt_alive;
		__u32 rt_multi_hop;

		LIBCFS_IOC_INIT_V2(data, cfg_hdr);
		data.cfg_count = i;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_ROUTE, &data);
		if (rc != 0) {
			l_errno = errno;
			break;
		}

		/* filter on provided data */
		if (net != LNET_NET_ANY &&
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

			if (cYAML_create_number(item, "health_sensitivity",
						data.cfg_config_u.
						cfg_route.rtr_sensitivity) == NULL)
				goto out;

			rt_alive = data.cfg_config_u.cfg_route.rtr_flags &
					LNET_RT_ALIVE;
			rt_multi_hop = data.cfg_config_u.cfg_route.rtr_flags &
					LNET_RT_MULTI_HOP;

			if (!backup &&
			    cYAML_create_string(item, "state",
						rt_alive ?
						"up" : "down") == NULL)
				goto out;

			if (!backup &&
			    cYAML_create_string(item, "type",
						rt_multi_hop?
						"multi-hop" : "single-hop") == NULL)
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

static int lustre_lnet_queryip(struct lnet_dlc_intf_descr *intf, __u32 *ip)
{
	struct ifreq ifr;
	int rc;

	memset(&ifr, 0, sizeof(ifr));
	rc = socket_intf_query(SIOCGIFFLAGS, intf->intf_name, &ifr);
	if (rc != 0)
		return LUSTRE_CFG_RC_BAD_PARAM;

	if ((ifr.ifr_flags & IFF_UP) == 0)
		return LUSTRE_CFG_RC_BAD_PARAM;

	memset(&ifr, 0, sizeof(ifr));
	rc = socket_intf_query(SIOCGIFADDR, intf->intf_name, &ifr);
	if (rc != 0)
		return LUSTRE_CFG_RC_BAD_PARAM;

	*ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	*ip = bswap_32(*ip);

	return LUSTRE_CFG_RC_NO_ERR;
}

/*
 * for each interface in the array of interfaces find the IP address of
 * that interface, create its nid and add it to an array of NIDs.
 * Stop if any of the interfaces is down
 */
static int lustre_lnet_intf2nids(struct lnet_dlc_network_descr *nw,
				 lnet_nid_t **nids, __u32 *nnids,
				 char *err_str, size_t str_len)
{
	int i = 0, count = 0, rc;
	struct lnet_dlc_intf_descr *intf;
	char val[LNET_MAX_STR_LEN];
	__u32 ip;
	int gni_num;
	char *endp;
	unsigned int num;


	if (nw == NULL || nids == NULL) {
		snprintf(err_str, str_len,
			 "\"unexpected parameters to lustre_lnet_intf2nids()\"");
		return LUSTRE_CFG_RC_BAD_PARAM;
	}

	if (LNET_NETTYP(nw->nw_id) == GNILND) {
		count = 1;
	} else {
		list_for_each_entry(intf, &nw->nw_intflist, intf_on_network)
			count++;
	}

	*nids = calloc(count, sizeof(lnet_nid_t));
	if (*nids == NULL) {
		snprintf(err_str, str_len,
			 "\"out of memory\"");
		return LUSTRE_CFG_RC_OUT_OF_MEM;
	}
	/*
	 * special case the GNI interface since it doesn't have an IP
	 * address. The assumption is that there can only be one GNI
	 * interface in the system. No interface name is provided.
	 */
	if (LNET_NETTYP(nw->nw_id) == GNILND) {
		rc = read_sysfs_file(gni_nid_path, "nid", val,
				1, sizeof(val));
		if (rc) {
			snprintf(err_str, str_len,
				 "\"cannot read gni nid\"");
			goto failed;
		}
		gni_num = atoi(val);

		(*nids)[i] = LNET_MKNID(nw->nw_id, gni_num);

		goto out;
	}

	/* look at the other interfaces */
	list_for_each_entry(intf, &nw->nw_intflist, intf_on_network) {
		if (LNET_NETTYP(nw->nw_id) == PTL4LND) {
			/* handle LNDs with numeric interface name */
			num = strtoul(intf->intf_name, &endp, 0);
			if (endp == intf->intf_name || *endp != '\0') {
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				snprintf(err_str, str_len,
					 "\"couldn't query intf %s\"",
					 intf->intf_name);
				goto failed;
			}
			(*nids)[i] = LNET_MKNID(nw->nw_id, num);
			i++;
		} else {
			/* handle LNDs with ip interface name */
			rc = lustre_lnet_queryip(intf, &ip);
			if (rc != LUSTRE_CFG_RC_NO_ERR) {
				snprintf(err_str, str_len,
					 "\"couldn't query intf %s\"",
					 intf->intf_name);
				goto failed;
			}
			(*nids)[i] = LNET_MKNID(nw->nw_id, ip);
			i++;
		}
	}

out:
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

static int lustre_lnet_resolve_ip2nets_rule(struct lustre_lnet_ip2nets *ip2nets,
					    lnet_nid_t **nids, __u32 *nnids,
					    char *err_str, size_t str_len)
{
	struct ifaddrs *ifa;
	int rc = LUSTRE_CFG_RC_NO_ERR;

	rc = getifaddrs(&ifa);
	if (rc < 0) {
		snprintf(err_str, str_len,
			 "\"failed to get interface addresses: %d\"", -errno);
		return -errno;
	}

	rc = lustre_lnet_match_ip_to_intf(ifa,
					  &ip2nets->ip2nets_net.nw_intflist,
					  &ip2nets->ip2nets_ip_ranges);
	if (rc != LUSTRE_CFG_RC_MATCH) {
		snprintf(err_str, str_len,
			 "\"couldn't match ip to existing interfaces\"");
		freeifaddrs(ifa);
		return rc;
	}

	rc = lustre_lnet_intf2nids(&ip2nets->ip2nets_net, nids, nnids,
				   err_str, str_len);
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
		strncpy(conf->lic_ni_intf, intf_descr->intf_name,
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
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";

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
	rc = lustre_lnet_resolve_ip2nets_rule(ip2nets, &nids, &nnids, err_str,
					      sizeof(err_str));
	if (rc != LUSTRE_CFG_RC_NO_ERR && rc != LUSTRE_CFG_RC_MATCH)
		goto out;

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
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	lnet_nid_t *nids = NULL;
	__u32 nnids = 0;
	size_t len;
	int count;
	struct lnet_dlc_intf_descr *intf_descr, *tmp;
	__u32 *cpt_array;

	if (ip2net == NULL && (nw_descr == NULL || nw_descr->nw_id == 0 ||
	    (list_empty(&nw_descr->nw_intflist) &&
	     LNET_NETTYP(nw_descr->nw_id) != GNILND))) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"missing mandatory parameters in NI config: '%s'\"",
			 (nw_descr == NULL) ? "network , interface" :
			 (nw_descr->nw_id == 0) ? "network" : "interface");
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

	if (nw_descr->nw_id == LNET_NET_ANY) {
		snprintf(err_str,
			sizeof(err_str),
			"\"cannot parse net '%s'\"",
			libcfs_net2str(nw_descr->nw_id));
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	/*
	 * special case the GNI since no interface name is expected
	 */
	if (list_empty(&nw_descr->nw_intflist) &&
	    (LNET_NETTYP(nw_descr->nw_id) != GNILND)) {
		snprintf(err_str,
			sizeof(err_str),
			"\"no interface name provided\"");
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	rc = lustre_lnet_intf2nids(nw_descr, &nids, &nnids,
				   err_str, sizeof(err_str));
	if (rc != 0) {
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
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	lnet_nid_t *nids = NULL;
	__u32 nnids = 0;
	struct lnet_dlc_intf_descr *intf_descr, *tmp;

	if (nw_descr == NULL || nw_descr->nw_id == 0) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"missing mandatory parameter in deleting NI: '%s'\"",
			 (nw_descr == NULL) ? "network , interface" :
			 (nw_descr->nw_id == 0) ? "network" : "interface");
		rc = LUSTRE_CFG_RC_MISSING_PARAM;
		goto out;
	}

	if (LNET_NETTYP(nw_descr->nw_id) == LOLND)
		return LUSTRE_CFG_RC_NO_ERR;

	if (nw_descr->nw_id == LNET_NET_ANY) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot parse net '%s'\"",
			 libcfs_net2str(nw_descr->nw_id));
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	rc = lustre_lnet_intf2nids(nw_descr, &nids, &nnids,
				   err_str, sizeof(err_str));
	if (rc != 0) {
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

static int
lustre_lnet_config_healthv(int value, bool all, lnet_nid_t nid,
			   enum lnet_health_type type, char *name,
			   int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_reset_health_cfg data;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";

	LIBCFS_IOC_INIT_V2(data, rh_hdr);
	data.rh_type = type;
	data.rh_all = all;
	data.rh_value = value;
	data.rh_nid = nid;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_SET_HEALHV, &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str), "Can not configure health value: %s",
			 strerror(errno));
	}

	cYAML_build_error(rc, seq_no, ADD_CMD, name, err_str, err_rc);

	return rc;
}

int lustre_lnet_config_ni_healthv(int value, bool all, char *ni_nid, int seq_no,
				  struct cYAML **err_rc)
{
	lnet_nid_t nid;
	if (ni_nid)
		nid = libcfs_str2nid(ni_nid);
	else
		nid = LNET_NID_ANY;
	return lustre_lnet_config_healthv(value, all, nid,
					  LNET_HEALTH_TYPE_LOCAL_NI,
					  "ni healthv", seq_no, err_rc);
}

int lustre_lnet_config_peer_ni_healthv(int value, bool all, char *lpni_nid,
				       int seq_no, struct cYAML **err_rc)
{
	lnet_nid_t nid;
	if (lpni_nid)
		nid = libcfs_str2nid(lpni_nid);
	else
		nid = LNET_NID_ANY;
	return lustre_lnet_config_healthv(value, all, nid,
					  LNET_HEALTH_TYPE_PEER_NI,
					  "peer_ni healthv", seq_no, err_rc);
}

static bool
add_msg_stats_to_yaml_blk(struct cYAML *yaml,
			  struct lnet_ioctl_comm_count *counts)
{
	if (cYAML_create_number(yaml, "put",
				counts->ico_put_count)
					== NULL)
		return false;
	if (cYAML_create_number(yaml, "get",
				counts->ico_get_count)
					== NULL)
		return false;
	if (cYAML_create_number(yaml, "reply",
				counts->ico_reply_count)
					== NULL)
		return false;
	if (cYAML_create_number(yaml, "ack",
				counts->ico_ack_count)
					== NULL)
		return false;
	if (cYAML_create_number(yaml, "hello",
				counts->ico_hello_count)
					== NULL)
		return false;

	return true;
}

static struct lnet_ioctl_comm_count *
get_counts(struct lnet_ioctl_element_msg_stats *msg_stats, int idx)
{
	if (idx == 0)
		return &msg_stats->im_send_stats;
	if (idx == 1)
		return &msg_stats->im_recv_stats;
	if (idx == 2)
		return &msg_stats->im_drop_stats;

	return NULL;
}

static int
create_local_udsp_info(struct lnet_ioctl_construct_udsp_info *udsp_info,
		       struct cYAML *net_node)
{
	char tmp[LNET_MAX_STR_LEN];
	struct cYAML *udsp_net;
	bool created = false;
	struct cYAML *pref;
	int i;

	/* add the UDSP info */
	udsp_net = cYAML_create_object(net_node, "udsp info");
	if (!udsp_net)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (!cYAML_create_number(udsp_net, "net priority",
				 (int) udsp_info->cud_net_priority))
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (!cYAML_create_number(udsp_net, "nid priority",
				 (int)udsp_info->cud_nid_priority))
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	pref = udsp_net;

	for (i = 0; i < LNET_MAX_SHOW_NUM_NID; i++) {
		memset(tmp, 0, LNET_MAX_STR_LEN);
		if (udsp_info->cud_pref_rtr_nid[i] == 0)
			break;
		if (!created) {
			pref = cYAML_create_object(udsp_net,
					"Preferred gateway NIDs");
			if (!pref)
				return LUSTRE_CFG_RC_OUT_OF_MEM;
			created = true;
		}
		snprintf(tmp, sizeof(tmp), "NID-%d", i);
		if (!cYAML_create_string(pref, tmp,
			libcfs_nid2str(udsp_info->cud_pref_rtr_nid[i])))
			return LUSTRE_CFG_RC_OUT_OF_MEM;
	}

	return LUSTRE_CFG_RC_NO_ERR;
}

static int
create_remote_udsp_info(struct lnet_ioctl_construct_udsp_info *udsp_info,
			struct cYAML *nid_node)
{
	char tmp[LNET_MAX_STR_LEN];
	struct cYAML *udsp_nid;
	bool created = false;
	struct cYAML *pref;
	int i;

	/* add the UDSP info */
	udsp_nid = cYAML_create_object(nid_node, "udsp info");
	if (!udsp_nid)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (!cYAML_create_number(udsp_nid, "net priority",
				 (int) udsp_info->cud_net_priority))
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (!cYAML_create_number(udsp_nid, "nid priority",
				 (int) udsp_info->cud_nid_priority))
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	pref = udsp_nid;
	for (i = 0; i < LNET_MAX_SHOW_NUM_NID; i++) {
		memset(tmp, 0, LNET_MAX_STR_LEN);
		if (udsp_info->cud_pref_rtr_nid[i] == 0)
			break;
		if (!created) {
			pref = cYAML_create_object(udsp_nid,
					"Preferred gateway NIDs");
			if (!pref)
				return LUSTRE_CFG_RC_OUT_OF_MEM;
			created = true;
		}
		snprintf(tmp, sizeof(tmp), "NID-%d", i);
		if (!cYAML_create_string(pref, tmp,
			libcfs_nid2str(udsp_info->cud_pref_rtr_nid[i])))
			return LUSTRE_CFG_RC_OUT_OF_MEM;
	}

	pref = udsp_nid;
	created = false;
	for (i = 0; i < LNET_MAX_SHOW_NUM_NID; i++) {
		memset(tmp, 0, LNET_MAX_STR_LEN);
		if (udsp_info->cud_pref_nid[i] == 0)
			break;
		if (!created) {
			pref = cYAML_create_object(udsp_nid,
					"Preferred source NIDs");
			if (!pref)
				return LUSTRE_CFG_RC_OUT_OF_MEM;
			created = true;
		}
		snprintf(tmp, sizeof(tmp), "NID-%d", i);
		if (!cYAML_create_string(pref, tmp,
			libcfs_nid2str(udsp_info->cud_pref_nid[i])))
			return LUSTRE_CFG_RC_OUT_OF_MEM;
	}

	return LUSTRE_CFG_RC_NO_ERR;
}

int lustre_lnet_show_net(char *nw, int detail, int seq_no,
			 struct cYAML **show_rc, struct cYAML **err_rc,
			 bool backup)
{
	char *buf;
	struct lnet_ioctl_config_ni *ni_data;
	struct lnet_ioctl_config_lnd_tunables *lnd;
	struct lnet_ioctl_element_stats *stats;
	struct lnet_ioctl_element_msg_stats msg_stats;
	struct lnet_ioctl_local_ni_hstats hstats;
	struct lnet_ioctl_construct_udsp_info udsp_info;
	__u32 net = LNET_NET_ANY;
	__u32 prev_net = LNET_NET_ANY;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM, i, j;
	int l_errno = 0;
	struct cYAML *root = NULL, *tunables = NULL,
		*net_node = NULL, *interfaces = NULL,
		*item = NULL, *first_seq = NULL,
		*tmp = NULL, *statistics = NULL,
		*yhstats = NULL;
	int str_buf_len = LNET_MAX_SHOW_NUM_CPT * 2;
	char str_buf[str_buf_len];
	char *pos;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";
	bool exist = false, new_net = true;
	int net_num = 0;
	size_t buf_size = sizeof(*ni_data) + sizeof(*lnd) + sizeof(*stats);

	buf = calloc(1, buf_size);
	if (buf == NULL)
		goto out;

	ni_data = (struct lnet_ioctl_config_ni *)buf;

	if (nw != NULL) {
		net = libcfs_str2net(nw);
		if (net == LNET_NET_ANY) {
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
		if (net != LNET_NET_ANY &&
		    net != rc_net)
			continue;

		/* if we're backing up don't store lo */
		if (backup && LNET_NETTYP(rc_net) == LOLND)
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

		if (!backup &&
		    cYAML_create_string(item, "nid",
					libcfs_nid2str(ni_data->lic_nid)) == NULL)
			goto out;

		if (!backup &&
		    cYAML_create_string(item,
					"status",
					(ni_data->lic_status ==
					  LNET_NI_STATUS_UP) ?
					    "up" : "down") == NULL)
			goto out;

		/* don't add interfaces unless there is at least one
		 * interface */
		if (strlen(ni_data->lic_ni_intf) > 0) {
			interfaces = cYAML_create_object(item, "interfaces");
			if (interfaces == NULL)
				goto out;

			snprintf(str_buf, sizeof(str_buf), "%d", 0);
			if (cYAML_create_string(interfaces, str_buf,
						ni_data->lic_ni_intf) == NULL)
				goto out;
		}

		if (detail) {
			char *limit;
			int k;

			if (backup)
				goto continue_without_msg_stats;

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

			if (detail < 4)
				goto continue_without_udsp_info;

			LIBCFS_IOC_INIT_V2(udsp_info, cud_hdr);
			udsp_info.cud_nid = ni_data->lic_nid;
			udsp_info.cud_peer = false;
			rc = l_ioctl(LNET_DEV_ID,
				     IOC_LIBCFS_GET_CONST_UDSP_INFO,
				     &udsp_info);
			if (rc != 0) {
				l_errno = errno;
				goto continue_without_udsp_info;
			}

			rc = create_local_udsp_info(&udsp_info, item);
			if (rc) {
				l_errno = errno;
				goto out;
			}

continue_without_udsp_info:
			if (detail < 2)
				goto continue_without_msg_stats;

			LIBCFS_IOC_INIT_V2(msg_stats, im_hdr);
			msg_stats.im_hdr.ioc_len = sizeof(msg_stats);
			msg_stats.im_idx = i;

			rc = l_ioctl(LNET_DEV_ID,
				     IOC_LIBCFS_GET_LOCAL_NI_MSG_STATS,
				     &msg_stats);
			if (rc != 0) {
				l_errno = errno;
				goto continue_without_msg_stats;
			}

			for (k = 0; k < 3; k++) {
				struct lnet_ioctl_comm_count *counts;
				struct cYAML *msg_statistics = NULL;

				msg_statistics = cYAML_create_object(item,
						 (char *)gmsg_stat_names[k]);
				if (msg_statistics == NULL)
					goto out;

				counts = get_counts(&msg_stats, k);
				if (counts == NULL)
					goto out;

				if (!add_msg_stats_to_yaml_blk(msg_statistics,
							       counts))
					goto out;
			}

			LIBCFS_IOC_INIT_V2(hstats, hlni_hdr);
			hstats.hlni_nid = ni_data->lic_nid;
			/* grab health stats */
			rc = l_ioctl(LNET_DEV_ID,
				     IOC_LIBCFS_GET_LOCAL_HSTATS,
				     &hstats);
			if (rc != 0) {
				l_errno = errno;
				goto continue_without_msg_stats;
			}
			yhstats = cYAML_create_object(item, "health stats");
			if (!yhstats)
				goto out;
			if (cYAML_create_number(yhstats, "health value",
						hstats.hlni_health_value)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "interrupts",
						hstats.hlni_local_interrupt)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "dropped",
						hstats.hlni_local_dropped)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "aborted",
						hstats.hlni_local_aborted)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "no route",
						hstats.hlni_local_no_route)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "timeouts",
						hstats.hlni_local_timeout)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "error",
						hstats.hlni_local_error)
							== NULL)
				goto out;

continue_without_msg_stats:
			tunables = cYAML_create_object(item, "tunables");
			if (!tunables)
				goto out;

			rc = lustre_net_show_tunables(tunables, &lnd->lt_cmn);
			if (rc != LUSTRE_CFG_RC_NO_ERR)
				goto out;

			rc = lustre_ni_show_tunables(tunables, LNET_NETTYP(rc_net),
						     &lnd->lt_tun);
			if (rc != LUSTRE_CFG_RC_NO_ERR &&
			    rc != LUSTRE_CFG_RC_NO_MATCH)
				goto out;

			if (rc != LUSTRE_CFG_RC_NO_MATCH) {
				tunables = cYAML_create_object(item,
							       "lnd tunables");
				if (tunables == NULL)
					goto out;
			}

			if (!backup &&
			    cYAML_create_number(item, "dev cpt",
						ni_data->lic_dev_cpt) == NULL)
				goto out;

			/* out put the CPTs in the format: "[x,x,x,...]" */
			pos = str_buf;
			limit = str_buf + str_buf_len - 3;
			pos += scnprintf(pos, limit - pos, "\"[");
			for (j = 0 ; ni_data->lic_ncpts >= 1 &&
				j < ni_data->lic_ncpts &&
				pos < limit; j++) {
				pos += scnprintf(pos, limit - pos,
						 "%d", ni_data->lic_cpts[j]);
				if ((j + 1) < ni_data->lic_ncpts)
					pos += scnprintf(pos, limit - pos, ",");
			}
			snprintf(pos, 3, "]\"");

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
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";

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

int ioctl_set_value(__u32 val, int ioc, char *name,
		    int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_set_value data;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";

	LIBCFS_IOC_INIT_V2(data, sv_hdr);
	data.sv_value = val;

	rc = l_ioctl(LNET_DEV_ID, ioc , &data);
	if (rc != 0) {
		rc = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot configure %s to %d: %s\"", name,
			 val, strerror(errno));
	}

	cYAML_build_error(rc, seq_no, ADD_CMD, name, err_str, err_rc);

	return rc;
}

int lustre_lnet_config_recov_intrv(int intrv, int seq_no, struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%d", intrv);

	rc = write_sysfs_file(modparam_path, "lnet_recovery_interval", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure recovery interval: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "recovery_interval", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_rtr_sensitivity(int sen, int seq_no, struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%d", sen);

	rc = write_sysfs_file(modparam_path, "router_sensitivity_percentage", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure router health sensitivity: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "router_sensitivity", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_hsensitivity(int sen, int seq_no, struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%d", sen);

	rc = write_sysfs_file(modparam_path, "lnet_health_sensitivity", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure health sensitivity: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "health_sensitivity", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_transaction_to(int timeout, int seq_no, struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%d", timeout);

	rc = write_sysfs_file(modparam_path, "lnet_transaction_timeout", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure transaction timeout: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "transaction_timeout", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_retry_count(int count, int seq_no, struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%d", count);

	rc = write_sysfs_file(modparam_path, "lnet_retry_count", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure retry count: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "retry_count", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_response_tracking(int val, int seq_no,
					 struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];
	char val_str[LNET_MAX_STR_LEN];

	if (val < 0 || val > 3) {
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		snprintf(err_str, sizeof(err_str),
			 "\"Valid values are: 0, 1, 2, or 3\"");
	} else {
		snprintf(err_str, sizeof(err_str), "\"success\"");

		snprintf(val_str, sizeof(val_str), "%d", val);

		rc = write_sysfs_file(modparam_path, "lnet_response_tracking",
				      val_str, 1, strlen(val_str) + 1);
		if (rc)
			snprintf(err_str, sizeof(err_str),
				 "\"cannot configure response tracking: %s\"",
				 strerror(errno));
	}

	cYAML_build_error(rc, seq_no, ADD_CMD, "response_tracking", err_str,
			  err_rc);

	return rc;
}

int lustre_lnet_config_recovery_limit(int val, int seq_no,
				      struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN];
	char val_str[LNET_MAX_STR_LEN];

	if (val < 0) {
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		snprintf(err_str, sizeof(err_str),
			 "\"Must be greater than or equal to 0\"");
	} else {
		snprintf(err_str, sizeof(err_str), "\"success\"");

		snprintf(val_str, sizeof(val_str), "%d", val);

		rc = write_sysfs_file(modparam_path, "lnet_recovery_limit",
				      val_str, 1, strlen(val_str) + 1);
		if (rc)
			snprintf(err_str, sizeof(err_str),
				 "\"cannot configure recovery limit: %s\"",
				 strerror(errno));
	}

	cYAML_build_error(rc, seq_no, ADD_CMD, "recovery_limit", err_str,
			  err_rc);

	return rc;
}

int lustre_lnet_config_max_intf(int max, int seq_no, struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%d", max);

	rc = write_sysfs_file(modparam_path, "lnet_interfaces_max", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure max interfaces: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "max_interfaces", err_str, err_rc);

	return rc;
}

int lustre_lnet_config_discovery(int enable, int seq_no, struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%u", (enable) ? 0 : 1);

	rc = write_sysfs_file(modparam_path, "lnet_peer_discovery_disabled", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure discovery: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "discovery", err_str, err_rc);

	return rc;

}

int lustre_lnet_config_drop_asym_route(int drop, int seq_no,
				       struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";
	char val[LNET_MAX_STR_LEN];

	snprintf(val, sizeof(val), "%u", (drop) ? 1 : 0);

	rc = write_sysfs_file(modparam_path, "lnet_drop_asym_route", val,
			      1, strlen(val) + 1);
	if (rc)
		snprintf(err_str, sizeof(err_str),
			 "\"cannot configure drop asym route: %s\"",
			 strerror(errno));

	cYAML_build_error(rc, seq_no, ADD_CMD, "drop_asym_route",
			  err_str, err_rc);

	return rc;

}

int lustre_lnet_config_numa_range(int range, int seq_no, struct cYAML **err_rc)
{
	return ioctl_set_value(range, IOC_LIBCFS_SET_NUMA_RANGE,
			       "numa_range", seq_no, err_rc);
}

int lustre_lnet_config_buffers(int tiny, int small, int large, int seq_no,
			       struct cYAML **err_rc)
{
	struct lnet_ioctl_config_data data;
	int rc = LUSTRE_CFG_RC_NO_ERR;
	char err_str[LNET_MAX_STR_LEN] = "\"success\"";

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
			     struct cYAML **err_rc, bool backup)
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
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";
	char node_name[LNET_MAX_STR_LEN];
	bool exist = false;

	buf = calloc(1, sizeof(*data) + sizeof(*pool_cfg));
	if (buf == NULL)
		goto out;

	data = (struct lnet_ioctl_config_data *)buf;

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	if (backup)
		pools_node = cYAML_create_object(root, "routing");
	else
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

		if (backup)
			goto calculate_buffers;

		snprintf(node_name, sizeof(node_name), "cpt[%d]", i);
		item = cYAML_create_seq_item(pools_node);
		if (item == NULL)
			goto out;

		if (first_seq == NULL)
			first_seq = item;

		cpt = cYAML_create_object(item, node_name);
		if (cpt == NULL)
			goto out;

calculate_buffers:
		/* create the tree  and print */
		for (j = 0; j < LNET_NRBPOOLS; j++) {
			if (!backup) {
				type_node = cYAML_create_object(cpt, pools[j]);
				if (type_node == NULL)
					goto out;
			}
			if (!backup &&
			    cYAML_create_number(type_node, "npages",
						pool_cfg->pl_pools[j].pl_npages)
			    == NULL)
				goto out;
			if (!backup &&
			    cYAML_create_number(type_node, "nbuffers",
						pool_cfg->pl_pools[j].
						  pl_nbuffers) == NULL)
				goto out;
			if (!backup &&
			    cYAML_create_number(type_node, "credits",
						pool_cfg->pl_pools[j].
						   pl_credits) == NULL)
				goto out;
			if (!backup &&
			    cYAML_create_number(type_node, "mincredits",
						pool_cfg->pl_pools[j].
						   pl_mincredits) == NULL)
				goto out;
			/* keep track of the total count for each of the
			 * tiny, small and large buffers */
			buf_count[j] += pool_cfg->pl_pools[j].pl_nbuffers;
		}
	}

	if (pool_cfg != NULL) {
		if (backup) {
			if (cYAML_create_number(pools_node, "enable",
						pool_cfg->pl_routing) ==
			NULL)
				goto out;

			goto add_buffer_section;
		}

		item = cYAML_create_seq_item(pools_node);
		if (item == NULL)
			goto out;

		if (cYAML_create_number(item, "enable", pool_cfg->pl_routing) ==
		    NULL)
			goto out;
	}

add_buffer_section:
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
			  struct cYAML **show_rc, struct cYAML **err_rc,
			  bool backup)
{
	/*
	 * TODO: This function is changing in a future patch to accommodate
	 * PEER_LIST and proper filtering on any nid of the peer
	 */
	struct lnet_ioctl_peer_cfg peer_info;
	struct lnet_peer_ni_credit_info *lpni_cri;
	struct lnet_ioctl_element_stats *lpni_stats;
	struct lnet_ioctl_element_msg_stats *msg_stats;
	struct lnet_ioctl_peer_ni_hstats *hstats;
	struct lnet_ioctl_construct_udsp_info udsp_info;
	lnet_nid_t *nidp;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	int i, j, k;
	int l_errno = 0;
	__u32 count;
	__u32 size;
	struct cYAML *root = NULL, *peer = NULL, *peer_ni = NULL,
		     *first_seq = NULL, *peer_root = NULL, *tmp = NULL,
		     *msg_statistics = NULL, *statistics = NULL,
		     *yhstats;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";
	struct lnet_process_id *list = NULL;
	void *data = NULL;
	void *lpni_data;
	bool exist = false;

	/* create struct cYAML root object */
	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	peer_root = cYAML_create_seq(root, "peer");
	if (peer_root == NULL)
		goto out;

	count = 1000;
	size = count * sizeof(struct lnet_process_id);
	list = malloc(size);
	if (list == NULL) {
		l_errno = ENOMEM;
		goto out;
	}
	if (knid != NULL) {
		list[0].nid = libcfs_str2nid(knid);
		count = 1;
	} else {
		for (;;) {
			memset(&peer_info, 0, sizeof(peer_info));
			LIBCFS_IOC_INIT_V2(peer_info, prcfg_hdr);
			peer_info.prcfg_hdr.ioc_len = sizeof(peer_info);
			peer_info.prcfg_size = size;
			peer_info.prcfg_bulk = list;

			l_errno = 0;
			rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_PEER_LIST,
				     &peer_info);
			count = peer_info.prcfg_count;
			if (rc == 0)
				break;
			l_errno = errno;
			if (l_errno != E2BIG) {
				snprintf(err_str,
					sizeof(err_str),
					"\"cannot get peer list: %s\"",
					strerror(l_errno));
				rc = -l_errno;
				goto out;
			}
			free(list);
			size = peer_info.prcfg_size;
			list = malloc(size);
			if (list == NULL) {
				l_errno = ENOMEM;
				goto out;
			}
		}
	}

	size = 4096;
	data = malloc(size);
	if (data == NULL) {
		l_errno = ENOMEM;
		goto out;
	}

	for (i = 0; i < count; i++) {
		for (;;) {
			memset(&peer_info, 0, sizeof(peer_info));
			LIBCFS_IOC_INIT_V2(peer_info, prcfg_hdr);
			peer_info.prcfg_hdr.ioc_len = sizeof(peer_info);
			peer_info.prcfg_prim_nid = list[i].nid;
			peer_info.prcfg_size = size;
			peer_info.prcfg_bulk = data;

			l_errno = 0;
			rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_PEER_NI,
				     &peer_info);
			if (rc == 0)
				break;
			l_errno = errno;
			if (l_errno != E2BIG) {
				snprintf(err_str,
					sizeof(err_str),
					"\"cannot get peer information: %s\"",
					strerror(l_errno));
				rc = -l_errno;
				goto out;
			}
			free(data);
			size = peer_info.prcfg_size;
			data = malloc(size);
			if (data == NULL) {
				l_errno = ENOMEM;
				goto out;
			}
		}
		exist = true;

		peer = cYAML_create_seq_item(peer_root);
		if (peer == NULL)
			goto out;

		if (first_seq == NULL)
			first_seq = peer;

		lnet_nid_t pnid = peer_info.prcfg_prim_nid;
		if (cYAML_create_string(peer, "primary nid",
					libcfs_nid2str(pnid))
		    == NULL)
			goto out;
		if (cYAML_create_string(peer, "Multi-Rail",
					peer_info.prcfg_mr ? "True" : "False")
		    == NULL)
			goto out;
		/*
		 * print out the state of the peer only if details are
		 * requested
		 */
		if (detail >= 3) {
			if (!backup &&
			    cYAML_create_number(peer, "peer state",
						peer_info.prcfg_state)
				== NULL)
				goto out;
		}

		tmp = cYAML_create_seq(peer, "peer ni");
		if (tmp == NULL)
			goto out;

		lpni_data = data;
		for (j = 0; j < peer_info.prcfg_count; j++) {
			nidp = lpni_data;
			lpni_cri = (void*)nidp + sizeof(nidp);
			lpni_stats = (void *)lpni_cri + sizeof(*lpni_cri);
			msg_stats = (void *)lpni_stats + sizeof(*lpni_stats);
			hstats = (void *)msg_stats + sizeof(*msg_stats);
			lpni_data = (void *)hstats + sizeof(*hstats);

			peer_ni = cYAML_create_seq_item(tmp);
			if (peer_ni == NULL)
				goto out;

			if (cYAML_create_string(peer_ni, "nid",
						libcfs_nid2str(*nidp))
			    == NULL)
				goto out;

			if (backup)
				continue;

			if (detail < 4)
				goto continue_without_udsp_info;

			LIBCFS_IOC_INIT_V2(udsp_info, cud_hdr);
			udsp_info.cud_nid = *nidp;
			udsp_info.cud_peer = true;
			rc = l_ioctl(LNET_DEV_ID,
					IOC_LIBCFS_GET_CONST_UDSP_INFO,
					&udsp_info);
			if (rc != 0) {
				l_errno = errno;
				goto continue_without_udsp_info;
			}

			rc = create_remote_udsp_info(&udsp_info, peer_ni);
			if (rc) {
				l_errno = errno;
				goto out;
			}

continue_without_udsp_info:
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

			if (cYAML_create_number(peer_ni, "refcount",
						lpni_cri->cr_refcount) == NULL)
				goto out;

			statistics = cYAML_create_object(peer_ni, "statistics");
			if (statistics == NULL)
				goto out;

			if (cYAML_create_number(statistics, "send_count",
						lpni_stats->iel_send_count)
			    == NULL)
				goto out;

			if (cYAML_create_number(statistics, "recv_count",
						lpni_stats->iel_recv_count)
			    == NULL)
				goto out;

			if (cYAML_create_number(statistics, "drop_count",
						lpni_stats->iel_drop_count)
			    == NULL)
				goto out;

			if (detail < 2)
				continue;

			for (k = 0; k < 3; k++) {
				struct lnet_ioctl_comm_count *counts;

				msg_statistics = cYAML_create_object(peer_ni,
						 (char *) gmsg_stat_names[k]);
				if (msg_statistics == NULL)
					goto out;

				counts = get_counts(msg_stats, k);
				if (counts == NULL)
					goto out;

				if (!add_msg_stats_to_yaml_blk(msg_statistics,
							       counts))
					goto out;
			}

			yhstats = cYAML_create_object(peer_ni, "health stats");
			if (!yhstats)
				goto out;
			if (cYAML_create_number(yhstats, "health value",
						hstats->hlpni_health_value)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "dropped",
						hstats->hlpni_remote_dropped)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "timeout",
						hstats->hlpni_remote_timeout)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "error",
						hstats->hlpni_remote_error)
							== NULL)
				goto out;
			if (cYAML_create_number(yhstats, "network timeout",
						hstats->hlpni_network_timeout)
							== NULL)
				goto out;
		}
	}

	/* print output iff show_rc is not provided */
	if (show_rc == NULL)
		cYAML_print_tree(root);

	snprintf(err_str, sizeof(err_str), "\"success\"");
	rc = LUSTRE_CFG_RC_NO_ERR;

out:
	free(list);
	free(data);
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR || !exist) {
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

int lustre_lnet_list_peer(int seq_no,
			  struct cYAML **show_rc, struct cYAML **err_rc)
{
	struct lnet_ioctl_peer_cfg peer_info;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	__u32 count;
	__u32 size;
	int i = 0;
	int l_errno = 0;
	struct cYAML *root = NULL, *list_root = NULL, *first_seq = NULL;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";
	struct lnet_process_id *list = NULL;

	memset(&peer_info, 0, sizeof(peer_info));

	/* create struct cYAML root object */
	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	list_root = cYAML_create_seq(root, "peer list");
	if (list_root == NULL)
		goto out;

	count = 1000;
	size = count * sizeof(struct lnet_process_id);
	list = malloc(size);
	if (list == NULL) {
		l_errno = ENOMEM;
		goto out;
	}
	for (;;) {
		LIBCFS_IOC_INIT_V2(peer_info, prcfg_hdr);
		peer_info.prcfg_hdr.ioc_len = sizeof(peer_info);
		peer_info.prcfg_size = size;
		peer_info.prcfg_bulk = list;

		l_errno = 0;
		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_PEER_LIST, &peer_info);
		count = peer_info.prcfg_count;
		if (rc == 0)
			break;
		l_errno = errno;
		if (l_errno != E2BIG) {
			snprintf(err_str,
				sizeof(err_str),
				"\"cannot get peer list: %s\"",
				strerror(l_errno));
			rc = -l_errno;
			goto out;
		}
		free(list);
		size = peer_info.prcfg_size;
		list = malloc(size);
		if (list == NULL) {
			l_errno = ENOMEM;
			goto out;
		}
	}

	/* count is now the actual number of ids in the list. */
	for (i = 0; i < count; i++) {
		if (cYAML_create_string(list_root, "nid",
					libcfs_nid2str(list[i].nid))
		    == NULL)
			goto out;
	}

	/* print output iff show_rc is not provided */
	if (show_rc == NULL)
		cYAML_print_tree(root);

	snprintf(err_str, sizeof(err_str), "\"success\"");
	rc = LUSTRE_CFG_RC_NO_ERR;

out:
	if (list != NULL)
		free(list);
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
			free(list_root);
			free(root);
		} else if (show_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
					     list_root);
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

static void add_to_global(struct cYAML *show_rc, struct cYAML *node,
			  struct cYAML *root)
{
	struct cYAML *show_node;

	show_node = cYAML_get_object_item(show_rc, "global");
	if (show_node != NULL)
		cYAML_insert_sibling(show_node->cy_child,
				     node->cy_child);
	else
		cYAML_insert_sibling(show_rc->cy_child,
				     node);
	free(root);
}

static int build_global_yaml_entry(char *err_str, int err_len, int seq_no,
				   char *name, __u64 value,
				   struct cYAML **show_rc,
				   struct cYAML **err_rc, int err)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	struct cYAML *root = NULL, *global = NULL;

	if (err) {
		rc = err;
		goto out;
	}

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	global = cYAML_create_object(root, "global");
	if (global == NULL)
		goto out;

	if (cYAML_create_number(global, name,
				value) == NULL)
		goto out;

	if (show_rc == NULL)
		cYAML_print_tree(root);

	snprintf(err_str, err_len, "\"success\"");

	rc = LUSTRE_CFG_RC_NO_ERR;

out:
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		add_to_global(*show_rc, global, root);
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, "global", err_str, err_rc);

	return rc;
}

static int ioctl_show_global_values(int ioc, int seq_no, char *name,
				    struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	struct lnet_ioctl_set_value data;
	int rc;
	int l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	LIBCFS_IOC_INIT_V2(data, sv_hdr);

	rc = l_ioctl(LNET_DEV_ID, ioc, &data);
	if (rc != 0) {
		l_errno = -errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get %s: %s\"",
			 name, strerror(l_errno));
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no, name,
				       data.sv_value, show_rc, err_rc, l_errno);
}

int lustre_lnet_show_recov_intrv(int seq_no, struct cYAML **show_rc,
				 struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int intrv = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_recovery_interval", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get recovery interval: %d\"", rc);
	} else {
		intrv = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "recovery_interval", intrv, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_show_hsensitivity(int seq_no, struct cYAML **show_rc,
				  struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int sen = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_health_sensitivity", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get health sensitivity: %d\"", rc);
	} else {
		sen = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "health_sensitivity", sen, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_show_rtr_sensitivity(int seq_no, struct cYAML **show_rc,
				     struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int sen = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "router_sensitivity_percentage", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get router sensitivity percentage: %d\"", rc);
	} else {
		sen = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "router_sensitivity", sen, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_show_lnd_timeout(int seq_no, struct cYAML **show_rc,
				 struct cYAML **err_rc)
{
	char val[LNET_MAX_STR_LEN];
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";
	int lnd_to = -1;
	int l_errno = 0;
	int rc;
	int fd;
	glob_t path;

	rc = cfs_get_param_paths(&path, "lnet_lnd_timeout");
	if (rc < 0) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get LND timeout: %d\"", rc);
		return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
					       "lnd_timeout", lnd_to, show_rc,
					       err_rc, l_errno);
	}

	fd = open(path.gl_pathv[0], O_RDONLY);
	if (fd < 0) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"error opening %s\"", path.gl_pathv[0]);
		goto failed;
	}

	rc = read(fd, val, sizeof(val));
	if (rc < 0)
		l_errno = -errno;

	close(fd);

	if (rc < 0) {
		snprintf(err_str, sizeof(err_str),
			 "\"error reading %s\"", path.gl_pathv[0]);
		goto failed;
	}

	lnd_to = atoi(val);

failed:
	cfs_free_param_data(&path);

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "lnd_timeout", lnd_to, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_show_transaction_to(int seq_no, struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int tto = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_transaction_timeout", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get transaction timeout: %d\"", rc);
	} else {
		tto = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "transaction_timeout", tto, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_show_retry_count(int seq_no, struct cYAML **show_rc,
				 struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int retry_count = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_retry_count", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get retry count: %d\"", rc);
	} else {
		retry_count = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "retry_count", retry_count, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_calc_service_id(__u64 *service_id)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int service_port = -1, l_errno = 0;

	rc = read_sysfs_file(o2ib_modparam_path, "service", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = errno;
		fprintf(stderr, "error:\n    msg: \"cannot get service port: %s (%d)\"\n",
			strerror(l_errno), -l_errno);
		return rc;
	} else {
		service_port = atoi(val);
	}

	*service_id = htobe64(((__u64)RDMA_PS_TCP << 16) + service_port);

	return LUSTRE_CFG_RC_NO_ERR;
}

int show_recovery_queue(enum lnet_health_type type, char *name, int seq_no,
			struct cYAML **show_rc, struct cYAML **err_rc)
{
	struct lnet_ioctl_recovery_list nid_list;
	struct cYAML *root = NULL, *nids = NULL;
	int rc, i;
	char err_str[LNET_MAX_STR_LEN] = "failed to print recovery queue\n";

	LIBCFS_IOC_INIT_V2(nid_list, rlst_hdr);
	nid_list.rlst_type = type;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_RECOVERY_QUEUE, &nid_list);
	if (rc) {
		rc = errno;
		goto out;
	}

	if (nid_list.rlst_num_nids == 0)
		goto out;

	root = cYAML_create_object(NULL, NULL);
	if (root == NULL)
		goto out;

	nids = cYAML_create_object(root, name);
	if (nids == NULL)
		goto out;

	rc = -EINVAL;

	for (i = 0; i < nid_list.rlst_num_nids; i++) {
		char nidenum[LNET_MAX_STR_LEN];
		snprintf(nidenum, sizeof(nidenum), "nid-%d", i);
		if (!cYAML_create_string(nids, nidenum,
			libcfs_nid2str(nid_list.rlst_nid_array[i])))
			goto out;
	}

	snprintf(err_str, sizeof(err_str), "success\n");

	rc = 0;

out:
	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		struct cYAML *show_node;
		/* find the net node, if one doesn't exist
		 * then insert one.  Otherwise add to the one there
		 */
		show_node = cYAML_get_object_item(*show_rc, name);
		if (show_node != NULL && cYAML_is_sequence(show_node)) {
			cYAML_insert_child(show_node, nids);
			free(nids);
			free(root);
		} else if (show_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
						nids);
			free(root);
		} else {
			cYAML_free_tree(root);
		}
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, name, err_str, err_rc);

	return rc;
}

int lustre_lnet_show_local_ni_recovq(int seq_no, struct cYAML **show_rc,
				     struct cYAML **err_rc)
{
	return show_recovery_queue(LNET_HEALTH_TYPE_LOCAL_NI, "local NI recovery",
				   seq_no, show_rc, err_rc);
}

int lustre_lnet_show_peer_ni_recovq(int seq_no, struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	return show_recovery_queue(LNET_HEALTH_TYPE_PEER_NI, "peer NI recovery",
				   seq_no, show_rc, err_rc);
}

int lustre_lnet_show_response_tracking(int seq_no, struct cYAML **show_rc,
				       struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int rsp_tracking = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_response_tracking", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get lnet_response_tracking value: %d\"", rc);
	} else {
		rsp_tracking = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "response_tracking", rsp_tracking,
				       show_rc, err_rc, l_errno);
}

int lustre_lnet_show_recovery_limit(int seq_no, struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int recov_limit = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN];

	snprintf(err_str, sizeof(err_str), "\"out of memory\"");

	rc = read_sysfs_file(modparam_path, "lnet_recovery_limit", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get lnet_recovery_limit value: %d\"", rc);
	} else {
		recov_limit = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "recovery_limit", recov_limit,
				       show_rc, err_rc, l_errno);
}

int lustre_lnet_show_max_intf(int seq_no, struct cYAML **show_rc,
			      struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int max_intf = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_interfaces_max", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get max interfaces: %d\"", rc);
	} else {
		max_intf = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "max_interfaces", max_intf, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_show_discovery(int seq_no, struct cYAML **show_rc,
			       struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int discovery = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN]  = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_peer_discovery_disabled", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get discovery setting: %d\"", rc);
	} else {
		/*
		 * The kernel stores a discovery disabled value. User space
		 * shows whether discovery is enabled. So the value must be
		 * inverted.
		 */
		discovery = !atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "discovery", discovery, show_rc,
				       err_rc, l_errno);
}

int lustre_lnet_show_drop_asym_route(int seq_no, struct cYAML **show_rc,
				     struct cYAML **err_rc)
{
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	char val[LNET_MAX_STR_LEN];
	int drop_asym_route = -1, l_errno = 0;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";

	rc = read_sysfs_file(modparam_path, "lnet_drop_asym_route", val,
			     1, sizeof(val));
	if (rc) {
		l_errno = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot get drop asym route setting: %d\"", rc);
	} else {
		drop_asym_route = atoi(val);
	}

	return build_global_yaml_entry(err_str, sizeof(err_str), seq_no,
				       "drop_asym_route", drop_asym_route,
				       show_rc, err_rc, l_errno);
}

int lustre_lnet_show_numa_range(int seq_no, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	return ioctl_show_global_values(IOC_LIBCFS_GET_NUMA_RANGE, seq_no,
					"numa_range", show_rc, err_rc);
}

int lustre_lnet_show_stats(int seq_no, struct cYAML **show_rc,
			   struct cYAML **err_rc)
{
	struct lnet_ioctl_lnet_stats data;
	struct lnet_counters *cntrs;
	int rc;
	int l_errno;
	char err_str[LNET_MAX_STR_LEN] = "\"out of memory\"";
	struct cYAML *root = NULL, *stats = NULL;

	LIBCFS_IOC_INIT_V2(data, st_hdr);

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_LNET_STATS, &data);
	if (rc) {
		l_errno = errno;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get lnet statistics: %s\"",
			 strerror(l_errno));
		rc = -l_errno;
		goto out;
	}

	rc = LUSTRE_CFG_RC_OUT_OF_MEM;

	cntrs = &data.st_cntrs;

	root = cYAML_create_object(NULL, NULL);
	if (!root)
		goto out;

	stats = cYAML_create_object(root, "statistics");
	if (!stats)
		goto out;

	if (!cYAML_create_number(stats, "msgs_alloc",
				 cntrs->lct_common.lcc_msgs_alloc))
		goto out;

	if (!cYAML_create_number(stats, "msgs_max",
				 cntrs->lct_common.lcc_msgs_max))
		goto out;

	if (!cYAML_create_number(stats, "rst_alloc",
				 cntrs->lct_health.lch_rst_alloc))
		goto out;

	if (!cYAML_create_number(stats, "errors",
				 cntrs->lct_common.lcc_errors))
		goto out;

	if (!cYAML_create_number(stats, "send_count",
				 cntrs->lct_common.lcc_send_count))
		goto out;

	if (!cYAML_create_number(stats, "resend_count",
				 cntrs->lct_health.lch_resend_count))
		goto out;

	if (!cYAML_create_number(stats, "response_timeout_count",
				 cntrs->lct_health.lch_response_timeout_count))
		goto out;

	if (!cYAML_create_number(stats, "local_interrupt_count",
				 cntrs->lct_health.lch_local_interrupt_count))
		goto out;

	if (!cYAML_create_number(stats, "local_dropped_count",
				 cntrs->lct_health.lch_local_dropped_count))
		goto out;

	if (!cYAML_create_number(stats, "local_aborted_count",
				 cntrs->lct_health.lch_local_aborted_count))
		goto out;

	if (!cYAML_create_number(stats, "local_no_route_count",
				 cntrs->lct_health.lch_local_no_route_count))
		goto out;

	if (!cYAML_create_number(stats, "local_timeout_count",
				 cntrs->lct_health.lch_local_timeout_count))
		goto out;

	if (!cYAML_create_number(stats, "local_error_count",
				 cntrs->lct_health.lch_local_error_count))
		goto out;

	if (!cYAML_create_number(stats, "remote_dropped_count",
				 cntrs->lct_health.lch_remote_dropped_count))
		goto out;

	if (!cYAML_create_number(stats, "remote_error_count",
				 cntrs->lct_health.lch_remote_error_count))
		goto out;

	if (!cYAML_create_number(stats, "remote_timeout_count",
				 cntrs->lct_health.lch_remote_timeout_count))
		goto out;

	if (!cYAML_create_number(stats, "network_timeout_count",
				 cntrs->lct_health.lch_network_timeout_count))
		goto out;

	if (!cYAML_create_number(stats, "recv_count",
				 cntrs->lct_common.lcc_recv_count))
		goto out;

	if (!cYAML_create_number(stats, "route_count",
				 cntrs->lct_common.lcc_route_count))
		goto out;

	if (!cYAML_create_number(stats, "drop_count",
				 cntrs->lct_common.lcc_drop_count))
		goto out;

	if (!cYAML_create_number(stats, "send_length",
				 cntrs->lct_common.lcc_send_length))
		goto out;

	if (!cYAML_create_number(stats, "recv_length",
				 cntrs->lct_common.lcc_recv_length))
		goto out;

	if (!cYAML_create_number(stats, "route_length",
				 cntrs->lct_common.lcc_route_length))
		goto out;

	if (!cYAML_create_number(stats, "drop_length",
				 cntrs->lct_common.lcc_drop_length))
		goto out;

	if (!show_rc)
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
	struct cYAML *net, *gw, *hop, *prio, *sen, *seq_no;

	net = cYAML_get_object_item(tree, "net");
	gw = cYAML_get_object_item(tree, "gateway");
	hop = cYAML_get_object_item(tree, "hop");
	prio = cYAML_get_object_item(tree, "priority");
	sen = cYAML_get_object_item(tree, "health_sensitivity");
	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_config_route((net) ? net->cy_valuestring : NULL,
					(gw) ? gw->cy_valuestring : NULL,
					(hop) ? hop->cy_valueint : -1,
					(prio) ? prio->cy_valueint : -1,
					(sen) ? sen->cy_valueint : -1,
					(seq_no) ? seq_no->cy_valueint : -1,
					err_rc);
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

/* Create a nidstring parseable by the nidstrings library from the nid
 * information encoded in the CYAML structure.
 * NOTE: Caller must free memory allocated to nidstr
 */
static int yaml_nids2nidstr(struct cYAML *nids_entry, char **nidstr,
			    char *prim_nid, int cmd)
{
	int num_strs = 0, rc;
	size_t buf_size, buf_pos, nidstr_len = 0;
	char *buffer;
	struct cYAML *child = NULL, *entry = NULL;

	if (cYAML_is_sequence(nids_entry)) {
		while (cYAML_get_next_seq_item(nids_entry, &child)) {
			entry = cYAML_get_object_item(child, "nid");
			/* don't count an empty entry */
			if (!entry || !entry->cy_valuestring)
				continue;

			if (prim_nid &&
			    (strcmp(entry->cy_valuestring, prim_nid) == 0)) {
				if (cmd == LNETCTL_DEL_CMD) {
					/*
					 * primary nid is present in the list of
					 * nids so that means we want to delete
					 * the entire peer, so no need to go
					 * further. Just delete the entire peer.
					 */
					return LUSTRE_CFG_RC_NO_ERR;
				} else {
					continue;
				}
			}

			/*
			 * + 1 for the space separating each string, and
			 * accounts for the terminating null char
			 */
			nidstr_len += strlen(entry->cy_valuestring) + 1;
			num_strs++;
		}
	}

	if (num_strs == 0 && !prim_nid)
		return LUSTRE_CFG_RC_MISSING_PARAM;
	else if (num_strs == 0) /* Only the primary nid was given to add/del */
		return LUSTRE_CFG_RC_NO_ERR;

	buffer = malloc(nidstr_len);
	if (!buffer)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	/* now grab all the nids */
	rc = 0;
	buf_pos = 0;
	buf_size = nidstr_len;
	child = NULL;
	while (cYAML_get_next_seq_item(nids_entry, &child)) {
		entry = cYAML_get_object_item(child, "nid");
		if (!entry || !entry->cy_valuestring)
			continue;

		if (prim_nid &&
		    (strcmp(entry->cy_valuestring, prim_nid) == 0))
			continue;

		if (buf_pos) {
			rc = snprintf(buffer + buf_pos, buf_size, " ");
			buf_pos += (rc < buf_size) ? rc : buf_size;
			buf_size = nidstr_len - buf_pos;
		}

		rc = snprintf(buffer + buf_pos, buf_size, "%s",
			      entry->cy_valuestring);
		buf_pos += (rc < buf_size) ? rc : buf_size;
		buf_size = nidstr_len - buf_pos;
	}

	*nidstr = buffer;

	return LUSTRE_CFG_RC_NO_ERR;
}

static int handle_yaml_peer_common(struct cYAML *tree, struct cYAML **show_rc,
				   struct cYAML **err_rc, int cmd)
{
	int rc, num_nids = 0, seqn;
	bool mr_value = false;
	char *nidstr = NULL, *prim_nidstr;
	char err_str[LNET_MAX_STR_LEN];
	struct cYAML *seq_no, *prim_nid, *mr, *peer_nis;
	lnet_nid_t lnet_nidlist[LNET_MAX_NIDS_PER_PEER];
	lnet_nid_t pnid = LNET_NID_ANY;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	seqn = seq_no ? seq_no->cy_valueint : -1;

	prim_nid = cYAML_get_object_item(tree, "primary nid");
	peer_nis = cYAML_get_object_item(tree, "peer ni");
	if (!prim_nid) {
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "\"primary nid\" must be specified");
		goto failed;
	}

	prim_nidstr = prim_nid->cy_valuestring;

	/* if the provided primary NID is bad, no need to go any further */
	pnid = libcfs_str2nid(prim_nidstr);
	if (pnid == LNET_NID_ANY) {
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		snprintf(err_str, LNET_MAX_STR_LEN,
			"badly formatted primary NID: %s", prim_nidstr);
		goto failed;
	}

	rc = yaml_nids2nidstr(peer_nis, &nidstr, prim_nidstr, cmd);
	if (rc == LUSTRE_CFG_RC_MISSING_PARAM) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "No nids defined in YAML block");
		goto failed;
	} else if (rc == LUSTRE_CFG_RC_OUT_OF_MEM) {
		snprintf(err_str, LNET_MAX_STR_LEN, "out of memory");
		goto failed;
	} else if (rc != LUSTRE_CFG_RC_NO_ERR) {
		snprintf(err_str, LNET_MAX_STR_LEN,
			 "Unrecognized error %d", rc);
		goto failed;
	}

	num_nids = 0;
	if (nidstr) {
		num_nids = lustre_lnet_parse_nidstr(nidstr, lnet_nidlist,
						    LNET_MAX_NIDS_PER_PEER,
						    err_str);
		if (num_nids < 0) {
			rc = num_nids;
			goto failed;
		}
	}

	if (cmd == LNETCTL_ADD_CMD) {
		mr = cYAML_get_object_item(tree, "Multi-Rail");
		mr_value = true;
		if (mr && mr->cy_valuestring) {
			if (strcmp(mr->cy_valuestring, "False") == 0)
				mr_value = false;
			else if (strcmp(mr->cy_valuestring, "True") != 0) {
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				snprintf(err_str, LNET_MAX_STR_LEN,
					 "Multi-Rail must be set to \"True\" or \"False\" found \"%s\"",
					 mr->cy_valuestring);
				goto failed;
			}
		}
	}

	rc = lustre_lnet_mod_peer_nidlist(pnid, lnet_nidlist, cmd,
					  num_nids, mr_value, seqn,
					  err_rc);

failed:
	if (nidstr)
		free(nidstr);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_build_error(rc, seqn, "peer",
				  cmd == LNETCTL_ADD_CMD ? ADD_CMD : DEL_CMD,
				  err_str, err_rc);

	return rc;
}

static int handle_yaml_config_peer(struct cYAML *tree, struct cYAML **show_rc,
				   struct cYAML **err_rc)
{
	return handle_yaml_peer_common(tree, show_rc, err_rc, LNETCTL_ADD_CMD);
}

static int handle_yaml_del_peer(struct cYAML *tree, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	return handle_yaml_peer_common(tree, show_rc, err_rc, LNETCTL_DEL_CMD);
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
				      show_rc, err_rc, false);
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
				    show_rc, err_rc, false);
}

static int handle_yaml_show_routing(struct cYAML *tree, struct cYAML **show_rc,
				    struct cYAML **err_rc)
{
	struct cYAML *seq_no;

	seq_no = cYAML_get_object_item(tree, "seq_no");

	return lustre_lnet_show_routing((seq_no) ? seq_no->cy_valueint : -1,
					show_rc, err_rc, false);
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
				     show_rc, err_rc, false);
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

static int handle_yaml_del_udsp(struct cYAML *tree, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	struct cYAML *seq_no, *idx;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	idx = cYAML_get_object_item(tree, "idx");

	return lustre_lnet_del_udsp(idx ? idx->cy_valueint : -1,
				    seq_no ? seq_no->cy_valueint : -1,
				    err_rc);
}

static int handle_yaml_config_udsp(struct cYAML *tree, struct cYAML **show_rc,
				   struct cYAML **err_rc)
{
	struct cYAML *seq_no, *src, *rte, *dst, *prio, *idx;
	union lnet_udsp_action action;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	src = cYAML_get_object_item(tree, "src");
	rte = cYAML_get_object_item(tree, "rte");
	dst = cYAML_get_object_item(tree, "dst");
	prio = cYAML_get_object_item(tree, "priority");
	idx = cYAML_get_object_item(tree, "idx");

	action.udsp_priority = prio ? prio->cy_valueint : -1;

	return lustre_lnet_add_udsp(src ? src->cy_valuestring : NULL,
				    dst ? dst->cy_valuestring : NULL,
				    rte ? rte->cy_valuestring : NULL,
				    prio ? "priority" : "",
				    &action,
				    idx ? idx->cy_valueint : -1,
				    seq_no ? seq_no->cy_valueint : -1,
				    err_rc);
}

static int handle_yaml_show_udsp(struct cYAML *tree, struct cYAML **show_rc,
				 struct cYAML **err_rc)
{
	struct cYAML *seq_no;
	struct cYAML *idx;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	idx = cYAML_get_object_item(tree, "idx");

	return lustre_lnet_show_udsp(idx ? idx->cy_valueint : -1,
				     seq_no ? seq_no->cy_valueint : -1,
				     show_rc, err_rc);
}

static int handle_yaml_config_global_settings(struct cYAML *tree,
					      struct cYAML **show_rc,
					      struct cYAML **err_rc)
{
	struct cYAML *max_intf, *numa, *discovery, *retry, *tto, *seq_no,
		     *sen, *recov, *rsen, *drop_asym_route, *rsp_tracking,
		     *recov_limit;
	int rc = 0;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	max_intf = cYAML_get_object_item(tree, "max_interfaces");
	if (!max_intf) /* try legacy name */
		max_intf = cYAML_get_object_item(tree, "max_intf");
	if (max_intf)
		rc = lustre_lnet_config_max_intf(max_intf->cy_valueint,
						 seq_no ? seq_no->cy_valueint
							: -1,
						 err_rc);

	numa = cYAML_get_object_item(tree, "numa_range");
	if (numa)
		rc = lustre_lnet_config_numa_range(numa->cy_valueint,
						   seq_no ? seq_no->cy_valueint
							: -1,
						   err_rc);

	discovery = cYAML_get_object_item(tree, "discovery");
	if (discovery)
		rc = lustre_lnet_config_discovery(discovery->cy_valueint,
						  seq_no ? seq_no->cy_valueint
							: -1,
						  err_rc);

	drop_asym_route = cYAML_get_object_item(tree, "drop_asym_route");
	if (drop_asym_route)
		rc = lustre_lnet_config_drop_asym_route(
			drop_asym_route->cy_valueint,
			seq_no ? seq_no->cy_valueint : -1,
			err_rc);

	retry = cYAML_get_object_item(tree, "retry_count");
	if (retry)
		rc = lustre_lnet_config_retry_count(retry->cy_valueint,
						    seq_no ? seq_no->cy_valueint
							: -1,
						    err_rc);

	tto = cYAML_get_object_item(tree, "transaction_timeout");
	if (tto)
		rc = lustre_lnet_config_transaction_to(tto->cy_valueint,
						       seq_no ? seq_no->cy_valueint
								: -1,
						       err_rc);

	sen = cYAML_get_object_item(tree, "health_sensitivity");
	if (sen)
		rc = lustre_lnet_config_hsensitivity(sen->cy_valueint,
						     seq_no ? seq_no->cy_valueint
							: -1,
						     err_rc);

	recov = cYAML_get_object_item(tree, "recovery_interval");
	if (recov)
		rc = lustre_lnet_config_recov_intrv(recov->cy_valueint,
						    seq_no ? seq_no->cy_valueint
							: -1,
						    err_rc);

	rsen = cYAML_get_object_item(tree, "router_sensitivity");
	if (rsen)
		rc = lustre_lnet_config_rtr_sensitivity(rsen->cy_valueint,
						     seq_no ? seq_no->cy_valueint
							: -1,
						     err_rc);

	rsp_tracking = cYAML_get_object_item(tree, "response_tracking");
	if (rsp_tracking)
		rc = lustre_lnet_config_response_tracking(rsp_tracking->cy_valueint,
						     seq_no ? seq_no->cy_valueint
							: -1,
						     err_rc);

	recov_limit = cYAML_get_object_item(tree, "recovery_limit");
	if (recov_limit)
		rc = lustre_lnet_config_recovery_limit(recov_limit->cy_valueint,
						       seq_no ? seq_no->cy_valueint
							: -1,
						       err_rc);

	return rc;
}

static int handle_yaml_del_global_settings(struct cYAML *tree,
					   struct cYAML **show_rc,
					   struct cYAML **err_rc)
{
	struct cYAML *max_intf, *numa, *discovery, *seq_no, *drop_asym_route;
	int rc = 0;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	max_intf = cYAML_get_object_item(tree, "max_interfaces");
	if (!max_intf) /* try legacy name */
		max_intf = cYAML_get_object_item(tree, "max_intf");
	if (max_intf)
		rc = lustre_lnet_config_max_intf(LNET_INTERFACES_MAX_DEFAULT,
						 seq_no ? seq_no->cy_valueint
							: -1,
						 err_rc);

	numa = cYAML_get_object_item(tree, "numa_range");
	if (numa)
		rc = lustre_lnet_config_numa_range(0,
						   seq_no ? seq_no->cy_valueint
							: -1,
						   err_rc);

	/* peer discovery is enabled by default */
	discovery = cYAML_get_object_item(tree, "discovery");
	if (discovery)
		rc = lustre_lnet_config_discovery(1,
						  seq_no ? seq_no->cy_valueint
							: -1,
						  err_rc);

	/* asymmetrical route messages are accepted by default */
	drop_asym_route = cYAML_get_object_item(tree, "drop_asym_route");
	if (drop_asym_route)
		rc = lustre_lnet_config_drop_asym_route(
			0, seq_no ? seq_no->cy_valueint : -1, err_rc);

	return rc;
}

static int handle_yaml_show_global_settings(struct cYAML *tree,
					    struct cYAML **show_rc,
					    struct cYAML **err_rc)
{
	struct cYAML *max_intf, *numa, *discovery, *retry, *tto, *seq_no,
		     *sen, *recov, *rsen, *drop_asym_route, *rsp_tracking,
		     *recov_limit;
	int rc = 0;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	max_intf = cYAML_get_object_item(tree, "max_interfaces");
	if (!max_intf) /* try legacy name */
		max_intf = cYAML_get_object_item(tree, "max_intf");
	if (max_intf)
		rc = lustre_lnet_show_max_intf(seq_no ? seq_no->cy_valueint
							: -1,
						show_rc, err_rc);

	numa = cYAML_get_object_item(tree, "numa_range");
	if (numa)
		rc = lustre_lnet_show_numa_range(seq_no ? seq_no->cy_valueint
							: -1,
						 show_rc, err_rc);

	discovery = cYAML_get_object_item(tree, "discovery");
	if (discovery)
		rc = lustre_lnet_show_discovery(seq_no ? seq_no->cy_valueint
							: -1,
						show_rc, err_rc);

	drop_asym_route = cYAML_get_object_item(tree, "drop_asym_route");
	if (drop_asym_route)
		rc = lustre_lnet_show_drop_asym_route(
			seq_no ? seq_no->cy_valueint : -1,
			show_rc, err_rc);

	retry = cYAML_get_object_item(tree, "retry_count");
	if (retry)
		rc = lustre_lnet_show_retry_count(seq_no ? seq_no->cy_valueint
							: -1,
						  show_rc, err_rc);

	tto = cYAML_get_object_item(tree, "transaction_timeout");
	if (tto)
		rc = lustre_lnet_show_transaction_to(seq_no ? seq_no->cy_valueint
							: -1,
						     show_rc, err_rc);

	sen = cYAML_get_object_item(tree, "health_sensitivity");
	if (sen)
		rc = lustre_lnet_show_hsensitivity(seq_no ? seq_no->cy_valueint
							: -1,
						     show_rc, err_rc);

	recov = cYAML_get_object_item(tree, "recovery_interval");
	if (recov)
		rc = lustre_lnet_show_recov_intrv(seq_no ? seq_no->cy_valueint
							: -1,
						  show_rc, err_rc);

	rsen = cYAML_get_object_item(tree, "router_sensitivity");
	if (rsen)
		rc = lustre_lnet_show_hsensitivity(seq_no ? seq_no->cy_valueint
							: -1,
						     show_rc, err_rc);

	rsp_tracking = cYAML_get_object_item(tree, "response_tracking");
	if (rsp_tracking)
		rc = lustre_lnet_show_response_tracking(seq_no ?
							seq_no->cy_valueint :
							-1,
							show_rc, err_rc);

	recov_limit = cYAML_get_object_item(tree, "recovery_limit");
	if (recov_limit)
		rc = lustre_lnet_show_recovery_limit(seq_no ?
						     seq_no->cy_valueint :
						     -1,
						     show_rc, err_rc);

	return rc;
}

static int handle_yaml_ping(struct cYAML *tree, struct cYAML **show_rc,
			    struct cYAML **err_rc)
{
	struct cYAML *seq_no, *nid, *timeout;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	nid = cYAML_get_object_item(tree, "primary nid");
	timeout = cYAML_get_object_item(tree, "timeout");

	return lustre_lnet_ping_nid((nid) ? nid->cy_valuestring : NULL,
				    (timeout) ? timeout->cy_valueint : 1000,
				    (seq_no) ? seq_no->cy_valueint : -1,
				    show_rc, err_rc);
}

static int handle_yaml_discover(struct cYAML *tree, struct cYAML **show_rc,
				struct cYAML **err_rc)
{
	struct cYAML *seq_no, *nid, *force;

	seq_no = cYAML_get_object_item(tree, "seq_no");
	nid = cYAML_get_object_item(tree, "primary nid");
	force = cYAML_get_object_item(tree, "force");

	return lustre_lnet_discover_nid((nid) ? nid->cy_valuestring : NULL,
					(force) ? force->cy_valueint : 0,
					(seq_no) ? seq_no->cy_valueint : -1,
					show_rc, err_rc);
}

static int handle_yaml_no_op()
{
	return LUSTRE_CFG_RC_NO_ERR;
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
	{ .name = "statistics", .cb = handle_yaml_no_op },
	{ .name = "global",	.cb = handle_yaml_config_global_settings},
	{ .name = "numa",	.cb = handle_yaml_config_numa },
	{ .name = "ping",	.cb = handle_yaml_no_op },
	{ .name = "discover",	.cb = handle_yaml_no_op },
	{ .name = "udsp",	.cb = handle_yaml_config_udsp },
	{ .name = NULL } };

static struct lookup_cmd_hdlr_tbl lookup_del_tbl[] = {
	{ .name = "route",	.cb = handle_yaml_del_route },
	{ .name = "net",	.cb = handle_yaml_del_ni },
	{ .name = "ip2nets",	.cb = handle_yaml_no_op },
	{ .name = "peer",	.cb = handle_yaml_del_peer },
	{ .name = "routing",	.cb = handle_yaml_del_routing },
	{ .name = "buffers",	.cb = handle_yaml_no_op },
	{ .name = "statistics", .cb = handle_yaml_no_op },
	{ .name = "global",	.cb = handle_yaml_del_global_settings},
	{ .name = "numa",	.cb = handle_yaml_del_numa },
	{ .name = "ping",	.cb = handle_yaml_no_op },
	{ .name = "discover",	.cb = handle_yaml_no_op },
	{ .name = "udsp",	.cb = handle_yaml_del_udsp },
	{ .name = NULL } };

static struct lookup_cmd_hdlr_tbl lookup_show_tbl[] = {
	{ .name = "route",	.cb = handle_yaml_show_route },
	{ .name = "net",	.cb = handle_yaml_show_net },
	{ .name = "peer",	.cb = handle_yaml_show_peers },
	{ .name = "ip2nets",	.cb = handle_yaml_no_op },
	{ .name = "routing",	.cb = handle_yaml_show_routing },
	{ .name = "buffers",	.cb = handle_yaml_show_routing },
	{ .name = "statistics",	.cb = handle_yaml_show_stats },
	{ .name = "global",	.cb = handle_yaml_show_global_settings},
	{ .name = "numa",	.cb = handle_yaml_show_numa },
	{ .name = "ping",	.cb = handle_yaml_no_op },
	{ .name = "discover",	.cb = handle_yaml_no_op },
	{ .name = "udsp",	.cb = handle_yaml_show_udsp },
	{ .name = NULL } };

static struct lookup_cmd_hdlr_tbl lookup_exec_tbl[] = {
	{ .name = "route",	.cb = handle_yaml_no_op },
	{ .name = "net",	.cb = handle_yaml_no_op },
	{ .name = "peer",	.cb = handle_yaml_no_op },
	{ .name = "ip2nets",	.cb = handle_yaml_no_op },
	{ .name = "routing",	.cb = handle_yaml_no_op },
	{ .name = "buffers",	.cb = handle_yaml_no_op },
	{ .name = "statistics",	.cb = handle_yaml_no_op },
	{ .name = "global",	.cb = handle_yaml_no_op },
	{ .name = "numa",	.cb = handle_yaml_no_op },
	{ .name = "ping",	.cb = handle_yaml_ping },
	{ .name = "discover",	.cb = handle_yaml_discover },
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

int lustre_yaml_exec(char *f, struct cYAML **show_rc, struct cYAML **err_rc)
{
	return lustre_yaml_cb_helper(f, lookup_exec_tbl,
				     show_rc, err_rc);
}
