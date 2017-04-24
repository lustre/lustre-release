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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/parser.h>
#include <lnet/lnetctl.h>
#include <lnet/nidstr.h>
#include <cyaml.h>
#include "lnetconfig/liblnetconfig.h"

#define LNET_CONFIGURE		true
#define LNET_UNCONFIGURE	false

static int jt_config_lnet(int argc, char **argv);
static int jt_unconfig_lnet(int argc, char **argv);
static int jt_add_route(int argc, char **argv);
static int jt_add_ni(int argc, char **argv);
static int jt_set_routing(int argc, char **argv);
static int jt_del_route(int argc, char **argv);
static int jt_del_ni(int argc, char **argv);
static int jt_show_route(int argc, char **argv);
static int jt_show_net(int argc, char **argv);
static int jt_show_routing(int argc, char **argv);
static int jt_show_stats(int argc, char **argv);
static int jt_show_peer(int argc, char **argv);
static int jt_show_numa(int argc, char **argv);
static int jt_set_tiny(int argc, char **argv);
static int jt_set_small(int argc, char **argv);
static int jt_set_large(int argc, char **argv);
static int jt_set_numa(int argc, char **argv);
static int jt_add_peer_nid(int argc, char **argv);
static int jt_del_peer_nid(int argc, char **argv);
/*static int jt_show_peer(int argc, char **argv);*/
static int lnetctl_list_commands(int argc, char **argv);

command_t lnet_cmds[] = {
	{"configure", jt_config_lnet, 0, "configure lnet\n"
	 "\t--all: load NI configuration from module parameters\n"},
	{"unconfigure", jt_unconfig_lnet, 0, "unconfigure lnet\n"},
	{ 0, 0, 0, NULL }
};

command_t route_cmds[] = {
	{"add", jt_add_route, 0, "add a route\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp)\n"
	 "\t--hop: number to final destination (1 < hops < 255)\n"
	 "\t--priority: priority of route (0 - highest prio\n"},
	{"del", jt_del_route, 0, "delete a route\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp)\n"},
	{"show", jt_show_route, 0, "show routes\n"
	 "\t--net: net name (e.g. tcp0) to filter on\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp) to filter on\n"
	 "\t--hop: number to final destination (1 < hops < 255) to filter on\n"
	 "\t--priority: priority of route (0 - highest prio to filter on\n"
	 "\t--verbose: display detailed output per route\n"},
	{ 0, 0, 0, NULL }
};

command_t net_cmds[] = {
	{"add", jt_add_ni, 0, "add a network\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--if: physical interface (e.g. eth0)\n"
	 "\t--ip2net: specify networks based on IP address patterns\n"
	 "\t--peer-timeout: time to wait before declaring a peer dead\n"
	 "\t--peer-credits: define the max number of inflight messages\n"
	 "\t--peer-buffer-credits: the number of buffer credits per peer\n"
	 "\t--credits: Network Interface credits\n"
	 "\t--cpt: CPU Partitions configured net uses (e.g. [0,1]\n"},
	{"del", jt_del_ni, 0, "delete a network\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--if: physical interface (e.g. eth0)\n"},
	{"show", jt_show_net, 0, "show networks\n"
	 "\t--net: net name (e.g. tcp0) to filter on\n"
	 "\t--verbose: display detailed output per network\n"},
	{ 0, 0, 0, NULL }
};

command_t routing_cmds[] = {
	{"show", jt_show_routing, 0, "show routing information\n"},
	{ 0, 0, 0, NULL }
};

command_t stats_cmds[] = {
	{"show", jt_show_stats, 0, "show LNET statistics\n"},
	{ 0, 0, 0, NULL }
};

command_t numa_cmds[] = {
	{"show", jt_show_numa, 0, "show NUMA range\n"},
	{ 0, 0, 0, NULL }
};

command_t set_cmds[] = {
	{"tiny_buffers", jt_set_tiny, 0, "set tiny routing buffers\n"
	 "\tVALUE must be greater than 0\n"},
	{"small_buffers", jt_set_small, 0, "set small routing buffers\n"
	 "\tVALUE must be greater than 0\n"},
	{"large_buffers", jt_set_large, 0, "set large routing buffers\n"
	 "\tVALUE must be greater than 0\n"},
	{"routing", jt_set_routing, 0, "enable/disable routing\n"
	 "\t0 - disable routing\n"
	 "\t1 - enable routing\n"},
	{"numa_range", jt_set_numa, 0, "set NUMA range for NI selection\n"
	 "\tVALUE must be at least 0\n"},
	{ 0, 0, 0, NULL }
};

command_t peer_cmds[] = {
	{"add", jt_add_peer_nid, 0, "add a peer NID\n"
	 "\t--prim_nid: Primary NID of the peer. If not provided then the first\n"
	 "\t            NID in the list becomes the Primary NID of a newly created\n"
	 "\t            peer. \n"
	 "\t--nid: one or more peer NIDs\n"
	 "\t--non_mr: create this peer as not Multi-Rail capable\n"},
	{"del", jt_del_peer_nid, 0, "delete a peer NID\n"
	 "\t--prim_nid: Primary NID of the peer.\n"
	 "\t--nid: list of NIDs to remove. If none provided,\n"
	 "\t       peer is deleted\n"},
	{"show", jt_show_peer, 0, "show peer information\n"
	 "\t--nid: NID of peer to filter on.\n"
	 "\t--verbose: Include  extended  statistics\n"},
	{ 0, 0, 0, NULL }
};

static inline void print_help(const command_t cmds[], const char *cmd_type,
			      const char *pc_name)
{
	const command_t *cmd;

	for (cmd = cmds; cmd->pc_name; cmd++) {
		if (pc_name != NULL &&
		    strcmp(cmd->pc_name, pc_name) == 0) {
			printf("%s %s: %s\n", cmd_type, cmd->pc_name,
			       cmd->pc_help);
			return;
		} else if (pc_name != NULL) {
			continue;
		}
		printf("%s %s: %s\n", cmd_type, cmd->pc_name, cmd->pc_help);
	}
}

static int parse_long(const char *number, long int *value)
{
	char *end;

	*value = strtol(number,  &end, 0);
	if (end != NULL && *end != 0)
		return -1;

	return 0;
}

static int handle_help(const command_t *cmd_list, const char *cmd,
		       const char *sub_cmd, int argc, char **argv)
{
	int opt;
	int rc = -1;
	optind = 0;
	opterr = 0;

	const char *const short_options = "h";
	static const struct option long_options[] = {
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL }
	};

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_help(cmd_list, cmd, sub_cmd);
			rc = 0;
			break;
		default:
			rc = -1;
			break;
		}
	}

	opterr = 1;
	optind = 0;
	return rc;
}

static int jt_set_numa(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	if (handle_help(set_cmds, "set", "numa_range", argc, argv) == 0)
		return 0;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse numa_range value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_numa_range(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_tiny(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	if (handle_help(set_cmds, "set", "tiny_buffers", argc, argv) == 0)
		return 0;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse tiny_buffers value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_buffers(value, -1, -1, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_small(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	if (handle_help(set_cmds, "set", "small_buffers", argc, argv) == 0)
		return 0;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse small_buffers value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_buffers(-1, value, -1, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_large(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	if (handle_help(set_cmds, "set", "large_buffers", argc, argv) == 0)
		return 0;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse large_buffers value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_buffers(-1, -1, value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_routing(int argc, char **argv)
{
	long int value;
	struct cYAML *err_rc = NULL;
	int rc;

	if (handle_help(set_cmds, "set", "routing", argc, argv) == 0)
		return 0;

	rc = parse_long(argv[1], &value);
	if (rc != 0 || (value != 0 && value != 1)) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse routing value.\n"
				  "must be 0 for disable or 1 for enable",
				  &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_enable_routing(value, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_config_lnet(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	bool load_mod_params = false;
	int rc, opt;

	const char *const short_options = "ah";
	static const struct option long_options[] = {
		{ .name = "all",  .has_arg = no_argument, .val = 'a' },
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL }
	};

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			load_mod_params = true;
			break;
		case 'h':
			print_help(lnet_cmds, "lnet", "configure");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_config_ni_system(LNET_CONFIGURE, load_mod_params,
					  -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_unconfig_lnet(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	int rc;

	if (handle_help(lnet_cmds, "lnet", "unconfigure", argc, argv) == 0)
		return 0;

	rc = lustre_lnet_config_ni_system(LNET_UNCONFIGURE, 0, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}
static int jt_add_route(int argc, char **argv)
{
	char *network = NULL, *gateway = NULL;
	long int hop = -1, prio = -1;
	struct cYAML *err_rc = NULL;
	int rc, opt;

	const char *const short_options = "n:g:c:p:h";
	static const struct option long_options[] = {
	{ .name = "net",       .has_arg = required_argument, .val = 'n' },
	{ .name = "gateway",   .has_arg = required_argument, .val = 'g' },
	{ .name = "hop-count", .has_arg = required_argument, .val = 'c' },
	{ .name = "priority",  .has_arg = required_argument, .val = 'p' },
	{ .name = "help",      .has_arg = no_argument,	     .val = 'h' },
	{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			network = optarg;
			break;
		case 'g':
			gateway = optarg;
			break;
		case 'c':
			rc = parse_long(optarg, &hop);
			if (rc != 0) {
				/* ignore option */
				hop = -1;
				continue;
			}
			break;
		case 'p':
			rc = parse_long(optarg, &prio);
			if (rc != 0) {
				/* ingore option */
				prio = -1;
				continue;
			}
			break;
		case 'h':
			print_help(route_cmds, "route", "add");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_config_route(network, gateway, hop, prio, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_add_ni(int argc, char **argv)
{
	char *ip2net = NULL;
	long int pto = -1, pc = -1, pbc = -1, cre = -1;
	struct cYAML *err_rc = NULL;
	int rc, opt, cpt_rc = -1;
	struct lnet_dlc_network_descr nw_descr;
	struct cfs_expr_list *global_cpts = NULL;
	struct lnet_ioctl_config_lnd_tunables tunables;
	bool found = false;

	memset(&tunables, 0, sizeof(tunables));
	lustre_lnet_init_nw_descr(&nw_descr);

	const char *const short_options = "n:i:p:t:c:b:r:s:h";
	static const struct option long_options[] = {
	{ .name = "net",	  .has_arg = required_argument, .val = 'n' },
	{ .name = "if",		  .has_arg = required_argument, .val = 'i' },
	{ .name = "ip2net",	  .has_arg = required_argument, .val = 'p' },
	{ .name = "peer-timeout", .has_arg = required_argument, .val = 't' },
	{ .name = "peer-credits", .has_arg = required_argument, .val = 'c' },
	{ .name = "peer-buffer-credits",
				  .has_arg = required_argument, .val = 'b' },
	{ .name = "credits",	  .has_arg = required_argument, .val = 'r' },
	{ .name = "cpt",	  .has_arg = required_argument, .val = 's' },
	{ .name = "help",	  .has_arg = no_argument,	.val = 'h' },
	{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nw_descr.nw_id = libcfs_str2net(optarg);
			break;
		case 'i':
			rc = lustre_lnet_parse_interfaces(optarg, &nw_descr);
			if (rc != 0) {
				cYAML_build_error(-1, -1, "ni", "add",
						"bad interface list",
						&err_rc);
				goto failed;
			}
			break;
		case 'p':
			ip2net = optarg;
			break;
		case 't':
			rc = parse_long(optarg, &pto);
			if (rc != 0) {
				/* ignore option */
				pto = -1;
				continue;
			}
			break;
		case 'c':
			rc = parse_long(optarg, &pc);
			if (rc != 0) {
				/* ignore option */
				pc = -1;
				continue;
			}
			break;
		case 'b':
			rc = parse_long(optarg, &pbc);
			if (rc != 0) {
				/* ignore option */
				pbc = -1;
				continue;
			}
			break;
		case 'r':
			rc = parse_long(optarg, &cre);
			if (rc != 0) {
				/* ignore option */
				cre = -1;
				continue;
			}
			break;
		case 's':
			cpt_rc = cfs_expr_list_parse(optarg,
						     strlen(optarg), 0,
						     UINT_MAX, &global_cpts);
			break;
		case 'h':
			print_help(net_cmds, "net", "add");
			return 0;
		default:
			return 0;
		}
	}

	if (pto > 0 || pc > 0 || pbc > 0 || cre > 0) {
		tunables.lt_cmn.lct_peer_timeout = pto;
		tunables.lt_cmn.lct_peer_tx_credits = pc;
		tunables.lt_cmn.lct_peer_rtr_credits = pbc;
		tunables.lt_cmn.lct_max_tx_credits = cre;
		found = true;
	}

	rc = lustre_lnet_config_ni(&nw_descr,
				   (cpt_rc == 0) ? global_cpts: NULL,
				   ip2net, (found) ? &tunables : NULL,
				   -1, &err_rc);

	if (global_cpts != NULL)
		cfs_expr_list_free(global_cpts);

failed:
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_del_route(int argc, char **argv)
{
	char *network = NULL, *gateway = NULL;
	struct cYAML *err_rc = NULL;
	int rc, opt;

	const char *const short_options = "n:g:h";
	static const struct option long_options[] = {
		{ .name = "net",     .has_arg = required_argument, .val = 'n' },
		{ .name = "gateway", .has_arg = required_argument, .val = 'g' },
		{ .name = "help",    .has_arg = no_argument,	   .val = 'h' },
		{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			network = optarg;
			break;
		case 'g':
			gateway = optarg;
			break;
		case 'h':
			print_help(route_cmds, "route", "del");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_del_route(network, gateway, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_del_ni(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	int rc, opt;
	struct lnet_dlc_network_descr nw_descr;

	lustre_lnet_init_nw_descr(&nw_descr);

	const char *const short_options = "n:i:h";
	static const struct option long_options[] = {
	{ .name = "net",	.has_arg = required_argument,	.val = 'n' },
	{ .name = "if",		.has_arg = required_argument,	.val = 'i' },
	{ .name = "help",	.has_arg = no_argument,		.val = 'h' },
	{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nw_descr.nw_id = libcfs_str2net(optarg);
			break;
		case 'i':
			rc = lustre_lnet_parse_interfaces(optarg, &nw_descr);
			if (rc != 0) {
				cYAML_build_error(-1, -1, "ni", "add",
						"bad interface list",
						&err_rc);
				goto out;
			}
			break;
		case 'h':
			print_help(net_cmds, "net", "del");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_del_ni(&nw_descr, -1, &err_rc);

out:
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_show_route(int argc, char **argv)
{
	char *network = NULL, *gateway = NULL;
	long int hop = -1, prio = -1;
	int detail = 0, rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;

	const char *const short_options = "n:g:h:p:vh";
	static const struct option long_options[] = {
	{ .name = "net",       .has_arg = required_argument, .val = 'n' },
	{ .name = "gateway",   .has_arg = required_argument, .val = 'g' },
	{ .name = "hop-count", .has_arg = required_argument, .val = 'c' },
	{ .name = "priority",  .has_arg = required_argument, .val = 'p' },
	{ .name = "verbose",   .has_arg = no_argument,	     .val = 'v' },
	{ .name = "help",      .has_arg = no_argument,	     .val = 'h' },
	{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			network = optarg;
			break;
		case 'g':
			gateway = optarg;
			break;
		case 'c':
			rc = parse_long(optarg, &hop);
			if (rc != 0) {
				/* ignore option */
				hop = -1;
				continue;
			}
			break;
		case 'p':
			rc = parse_long(optarg, &prio);
			if (rc != 0) {
				/* ignore option */
				prio = -1;
				continue;
			}
			break;
		case 'v':
			detail = 1;
			break;
		case 'h':
			print_help(route_cmds, "route", "show");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_route(network, gateway, hop, prio, detail, -1,
				    &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_show_net(int argc, char **argv)
{
	char *network = NULL;
	int detail = 0, rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;

	const char *const short_options = "n:vh";
	static const struct option long_options[] = {
		{ .name = "net",     .has_arg = required_argument, .val = 'n' },
		{ .name = "verbose", .has_arg = no_argument,	   .val = 'v' },
		{ .name = "help",    .has_arg = no_argument,	   .val = 'h' },
		{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			network = optarg;
			break;
		case 'v':
			detail = 1;
			break;
		case 'h':
			print_help(net_cmds, "net", "show");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_net(network, detail, -1, &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_show_routing(int argc, char **argv)
{
	struct cYAML *err_rc = NULL, *show_rc = NULL;
	int rc;

	if (handle_help(routing_cmds, "routing", "show", argc, argv) == 0)
		return 0;

	rc = lustre_lnet_show_routing(-1, &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_show_stats(int argc, char **argv)
{
	int rc;
	struct cYAML *show_rc = NULL, *err_rc = NULL;

	if (handle_help(stats_cmds, "stats", "show", argc, argv) == 0)
		return 0;

	rc = lustre_lnet_show_stats(-1, &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_show_numa(int argc, char **argv)
{
	int rc;
	struct cYAML *show_rc = NULL, *err_rc = NULL;

	if (handle_help(numa_cmds, "numa", "show", argc, argv) == 0)
		return 0;

	rc = lustre_lnet_show_numa_range(-1, &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static inline int jt_lnet(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2 &&
	    handle_help(lnet_cmds, "lnet", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], lnet_cmds);
}

static inline int jt_route(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2 &&
	    handle_help(route_cmds, "route", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], route_cmds);
}

static inline int jt_net(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2 &&
	    handle_help(net_cmds, "net", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], net_cmds);
}

static inline int jt_routing(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2 &&
	    handle_help(routing_cmds, "routing", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], routing_cmds);
}

static inline int jt_stats(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2 &&
	    handle_help(stats_cmds, "stats", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], stats_cmds);
}

static inline int jt_numa(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2 &&
	    handle_help(numa_cmds, "numa", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], numa_cmds);
}

static inline int jt_peers(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2 &&
	    handle_help(peer_cmds, "peer", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], peer_cmds);
}

static inline int jt_set(int argc, char **argv)
{
	if (argc < 2)
		return CMD_HELP;

	if (argc == 2  &&
	    handle_help(set_cmds, "set", NULL, argc, argv) == 0)
		return 0;

	return Parser_execarg(argc - 1, &argv[1], set_cmds);
}

static int jt_import(int argc, char **argv)
{
	char *file = NULL;
	struct cYAML *err_rc = NULL;
	struct cYAML *show_rc = NULL;
	int rc = 0, opt, opt_found = 0;
	char cmd = 'a';

	const char *const short_options = "adsh";
	static const struct option long_options[] = {
		{ .name = "add",  .has_arg = no_argument, .val = 'a' },
		{ .name = "del",  .has_arg = no_argument, .val = 'd' },
		{ .name = "show", .has_arg = no_argument, .val = 's' },
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		opt_found = 1;
		switch (opt) {
		case 'a':
		case 'd':
		case 's':
			cmd = opt;
			break;
		case 'h':
			printf("import FILE\n"
			       "import < FILE : import a file\n"
			       "\t--add: add configuration\n"
			       "\t--del: delete configuration\n"
			       "\t--show: show configuration\n"
			       "\t--help: display this help\n"
			       "If no command option is given then --add"
			       " is assumed by default\n");
			return 0;
		default:
			return 0;
		}
	}

	/* grab the file name if one exists */
	if (opt_found && argc == 3)
		file = argv[2];
	else if (!opt_found && argc == 2)
		file = argv[1];

	switch (cmd) {
	case 'a':
		rc = lustre_yaml_config(file, &err_rc);
		break;
	case 'd':
		rc = lustre_yaml_del(file, &err_rc);
		break;
	case 's':
		rc = lustre_yaml_show(file, &show_rc, &err_rc);
		cYAML_print_tree(show_rc);
		cYAML_free_tree(show_rc);
		break;
	}

	cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_export(int argc, char **argv)
{
	struct cYAML *show_rc = NULL;
	struct cYAML *err_rc = NULL;
	int rc, opt;
	FILE *f = NULL;

	const char *const short_options = "h";
	static const struct option long_options[] = {
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			printf("export FILE\n"
			       "export > FILE : export configuration\n"
			       "\t--help: display this help\n");
			return 0;
		default:
			return 0;
		}
	}

	if (argc >= 2) {
		f = fopen(argv[1], "w");
		if (f == NULL)
			return -1;
	} else
		f = stdout;

	rc = lustre_lnet_show_net(NULL, 1, -1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
	}

	rc = lustre_lnet_show_route(NULL, NULL, -1, -1, 1, -1, &show_rc,
				    &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
	}

	rc = lustre_lnet_show_routing(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
	}

	rc = lustre_lnet_show_peer(NULL, 1, -1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
	}

	rc = lustre_lnet_show_numa_range(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
	}

	if (show_rc != NULL) {
		cYAML_print_tree2file(f, show_rc);
		cYAML_free_tree(show_rc);
	}

	if (argc >= 2)
		fclose(f);

	return 0;
}

static int jt_add_peer_nid(int argc, char **argv)
{
	char *prim_nid = NULL;
	char **nids = NULL, **nids2 = NULL;
	int size = 0;
	struct cYAML *err_rc = NULL;
	int rc = LUSTRE_CFG_RC_NO_ERR, opt, i;
	bool non_mr = false;

	const char *const short_options = "k:n:mh";
	const struct option long_options[] = {
		{ "prim_nid", 1, NULL, 'k' },
		{ "nid", 1, NULL, 'n' },
		{ "non_mr", 0, NULL, 'm'},
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'k':
			prim_nid = optarg;
			break;
		case 'n':
			size = lustre_lnet_parse_nids(optarg, nids, size,
						      &nids2);
			if (nids2 == NULL)
				goto failed;
			nids = nids2;
			rc = LUSTRE_CFG_RC_OUT_OF_MEM;
			break;
		case 'm':
			non_mr = true;
			break;
		case 'h':
			print_help(peer_cmds, "peer", "add");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_config_peer_nid(prim_nid, nids, size,
					 !non_mr, -1, &err_rc);

failed:
	if (nids) {
		/* free the array of nids */
		for (i = 0; i < size; i++)
			free(nids[i]);
		free(nids);
	}

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_del_peer_nid(int argc, char **argv)
{
	char *prim_nid = NULL;
	char **nids = NULL, **nids2 = NULL;
	struct cYAML *err_rc = NULL;
	int rc = LUSTRE_CFG_RC_NO_ERR, opt, i, size = 0;

	const char *const short_options = "k:n:h";
	const struct option long_options[] = {
		{ "prim_nid", 1, NULL, 'k' },
		{ "nid", 1, NULL, 'n' },
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'k':
			prim_nid = optarg;
			break;
		case 'n':
			size = lustre_lnet_parse_nids(optarg, nids, size,
						      &nids2);
			if (nids2 == NULL)
				goto failed;
			nids = nids2;
			rc = LUSTRE_CFG_RC_OUT_OF_MEM;
			break;
		case 'h':
			print_help(peer_cmds, "peer", "del");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_del_peer_nid(prim_nid, nids, size, -1, &err_rc);

failed:
	if (nids) {
		for (i = 0; i < size; i++)
			free(nids[i]);
		free(nids);
	}

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_show_peer(int argc, char **argv)
{
	char *nid = NULL;
	int rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;
	int detail = 0;

	const char *const short_options = "n:vh";
	const struct option long_options[] = {
		{ "nid", 1, NULL, 'n' },
		{ "verbose", 0, NULL, 'v' },
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nid = optarg;
			break;
		case 'v':
			detail = 1;
			break;
		case 'h':
			print_help(peer_cmds, "peer", "show");
			return 0;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_peer(nid, detail, -1, &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

command_t list[] = {
	{"lnet", jt_lnet, 0, "lnet {configure | unconfigure} [--all]"},
	{"route", jt_route, 0, "route {add | del | show | help}"},
	{"net", jt_net, 0, "net {add | del | show | help}"},
	{"routing", jt_routing, 0, "routing {show | help}"},
	{"set", jt_set, 0, "set {tiny_buffers | small_buffers | large_buffers"
			   " | routing}"},
	{"import", jt_import, 0, "import {--add | --del | --show | "
				 "--help} FILE.yaml"},
	{"export", jt_export, 0, "export {--help} FILE.yaml"},
	{"stats", jt_stats, 0, "stats {show | help}"},
	{"numa", jt_numa, 0, "numa {show | help}"},
	{"peer", jt_peers, 0, "peer {add | del | show | help}"},
	{"help", Parser_help, 0, "help"},
	{"exit", Parser_quit, 0, "quit"},
	{"quit", Parser_quit, 0, "quit"},
	{"--list-commands", lnetctl_list_commands, 0, "list commands"},
	{ 0, 0, 0, NULL }
};

static int lnetctl_list_commands(int argc, char **argv)
{
	char buffer[81] = ""; /* 80 printable chars + terminating NUL */

	Parser_list_commands(list, buffer, sizeof(buffer), NULL, 0, 4);

	return 0;
}

int main(int argc, char **argv)
{
	int rc = 0;
	struct cYAML *err_rc = NULL;

	rc = lustre_lnet_config_lib_init();
	if (rc < 0) {
		cYAML_build_error(-1, -1, "lnetctl", "startup",
				  "cannot register LNet device", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		return rc;
	}

	Parser_init("lnetctl > ", list);
	if (argc > 1) {
		rc = Parser_execarg(argc - 1, &argv[1], list);
		goto errorout;
	}

	Parser_commands();

errorout:
	return rc;
}
