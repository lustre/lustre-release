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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/parser.h>
#include "lnetconfig/cyaml.h"
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
static int jt_show_recovery(int argc, char **argv);
static int jt_show_global(int argc, char **argv);
static int jt_show_udsp(int argc, char **argv);
static int jt_set_tiny(int argc, char **argv);
static int jt_set_small(int argc, char **argv);
static int jt_set_large(int argc, char **argv);
static int jt_set_numa(int argc, char **argv);
static int jt_set_retry_count(int argc, char **argv);
static int jt_set_transaction_to(int argc, char **argv);
static int jt_set_recov_intrv(int argc, char **argv);
static int jt_set_rtr_sensitivity(int argc, char **argv);
static int jt_set_hsensitivity(int argc, char **argv);
static int jt_add_peer_nid(int argc, char **argv);
static int jt_del_peer_nid(int argc, char **argv);
static int jt_set_max_intf(int argc, char **argv);
static int jt_set_discovery(int argc, char **argv);
static int jt_set_drop_asym_route(int argc, char **argv);
static int jt_list_peer(int argc, char **argv);
static int jt_add_udsp(int argc, char **argv);
static int jt_del_udsp(int argc, char **argv);
/*static int jt_show_peer(int argc, char **argv);*/
static int lnetctl_list_commands(int argc, char **argv);
static int jt_import(int argc, char **argv);
static int jt_export(int argc, char **argv);
static int jt_ping(int argc, char **argv);
static int jt_discover(int argc, char **argv);
static int jt_lnet(int argc, char **argv);
static int jt_route(int argc, char **argv);
static int jt_net(int argc, char **argv);
static int jt_routing(int argc, char **argv);
static int jt_set(int argc, char **argv);
static int jt_debug(int argc, char **argv);
static int jt_stats(int argc, char **argv);
static int jt_global(int argc, char **argv);
static int jt_peers(int argc, char **argv);
static int jt_set_ni_value(int argc, char **argv);
static int jt_set_peer_ni_value(int argc, char **argv);
static int jt_calc_service_id(int argc, char **argv);
static int jt_set_response_tracking(int argc, char **argv);
static int jt_set_recovery_limit(int argc, char **argv);
static int jt_udsp(int argc, char **argv);

command_t cmd_list[] = {
	{"lnet", jt_lnet, 0, "lnet {configure | unconfigure} [--all]"},
	{"route", jt_route, 0, "route {add | del | show | help}"},
	{"net", jt_net, 0, "net {add | del | show | help}"},
	{"routing", jt_routing, 0, "routing {show | help}"},
	{"set", jt_set, 0, "set {tiny_buffers | small_buffers | large_buffers"
			   " | routing | numa_range | max_interfaces"
			   " | discovery | drop_asym_route | retry_count"
			   " | transaction_timeout | health_sensitivity"
			   " | recovery_interval | router_sensitivity"
			   " | response_tracking | recovery_limit}"},
	{"import", jt_import, 0, "import FILE.yaml"},
	{"export", jt_export, 0, "export FILE.yaml"},
	{"stats", jt_stats, 0, "stats {show | help}"},
	{"debug", jt_debug, 0, "debug recovery {local | peer}"},
	{"global", jt_global, 0, "global {show | help}"},
	{"peer", jt_peers, 0, "peer {add | del | show | help}"},
	{"ping", jt_ping, 0, "ping nid,[nid,...]"},
	{"discover", jt_discover, 0, "discover nid[,nid,...]"},
	{"service-id", jt_calc_service_id, 0, "Calculate IB Lustre service ID\n"},
	{"udsp", jt_udsp, 0, "udsp {add | del | help}"},
	{"help", Parser_help, 0, "help"},
	{"exit", Parser_quit, 0, "quit"},
	{"quit", Parser_quit, 0, "quit"},
	{"--list-commands", lnetctl_list_commands, 0, "list commands"},
	{ 0, 0, 0, NULL }
};

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
	 "\t--priority: priority of route (0 - highest prio\n"
	 "\t--health_sensitivity: gateway health sensitivity (>= 1)\n"},
	{"del", jt_del_route, 0, "delete a route\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp)\n"},
	{"show", jt_show_route, 0, "show routes\n"
	 "\t--net: net name (e.g. tcp0) to filter on\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp) to filter on\n"
	 "\t--hop: number to final destination (1 < hops < 255) to filter on\n"
	 "\t--priority: priority of route (0 - highest prio to filter on\n"
	 "\t--health_sensitivity: gateway health sensitivity (>= 1)\n"
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
	 "\t--verbose: display detailed output per network."
		       " Optional argument of '2' outputs more stats\n"},
	{"set", jt_set_ni_value, 0, "set local NI specific parameter\n"
	 "\t--nid: NI NID to set the\n"
	 "\t--health: specify health value to set\n"
	 "\t--all: set all NIs value to the one specified\n"},
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

command_t debug_cmds[] = {
	{"recovery", jt_show_recovery, 0, "list recovery queues\n"
		"\t--local : list local recovery queue\n"
		"\t--peer : list peer recovery queue\n"},
	{ 0, 0, 0, NULL }
};

command_t global_cmds[] = {
	{"show", jt_show_global, 0, "show global variables\n"},
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
	{"max_interfaces", jt_set_max_intf, 0, "set the default value for "
		"max interfaces\n"
	 "\tValue must be greater than 16\n"},
	{"discovery", jt_set_discovery, 0, "enable/disable peer discovery\n"
	 "\t0 - disable peer discovery\n"
	 "\t1 - enable peer discovery (default)\n"},
	{"drop_asym_route", jt_set_drop_asym_route, 0,
	 "drop/accept asymmetrical route messages\n"
	 "\t0 - accept asymmetrical route messages (default)\n"
	 "\t1 - drop asymmetrical route messages\n"},
	{"retry_count", jt_set_retry_count, 0, "number of retries\n"
	 "\t0 - turn of retries\n"
	 "\t>0 - number of retries\n"},
	{"transaction_timeout", jt_set_transaction_to, 0, "Message/Response timeout\n"
	 "\t>0 - timeout in seconds\n"},
	{"health_sensitivity", jt_set_hsensitivity, 0, "sensitivity to failure\n"
	 "\t0 - turn off health evaluation\n"
	 "\t>0 - sensitivity value not more than 1000\n"},
	{"recovery_interval", jt_set_recov_intrv, 0, "interval to ping in seconds (at least 1)\n"
	 "\t>0 - time in seconds between pings\n"},
	{"router_sensitivity", jt_set_rtr_sensitivity, 0, "router sensitivity %\n"
	 "\t100 - router interfaces need to be fully healthy to be used\n"
	 "\t<100 - router interfaces can be used even if not healthy\n"},
	{"response_tracking", jt_set_response_tracking, 0,
	 "Set the behavior of response tracking\n"
	 "\t0 - Only LNet pings and discovery pushes utilize response tracking\n"
	 "\t1 - GETs are eligible for response tracking\n"
	 "\t2 - PUTs are eligible for response tracking\n"
	 "\t3 - Both PUTs and GETs are eligible for response tracking (default)\n"
	 "\tNote: Regardless of the value of the response_tracking parameter LNet\n"
	 "\t      pings and discovery pushes always utilize response tracking\n"},
	{"recovery_limit", jt_set_recovery_limit, 0,
	 "Set how long LNet will attempt to recover unhealthy interfaces.\n"
	 "\t0 - Recover indefinitely (default)\n"
	 "\t>0 - Recover for the specified number of seconds.\n"},
	{ 0, 0, 0, NULL }
};

command_t peer_cmds[] = {
	{"add", jt_add_peer_nid, 0, "add a peer NID\n"
	 "\t--prim_nid: Primary NID of the peer.\n"
	 "\t--nid: one or more peer NIDs\n"
	 "\t--non_mr: create this peer as not Multi-Rail capable\n"
	 "\t--ip2nets: specify a range of nids per peer"},
	{"del", jt_del_peer_nid, 0, "delete a peer NID\n"
	 "\t--prim_nid: Primary NID of the peer.\n"
	 "\t--nid: list of NIDs to remove. If none provided,\n"
	 "\t       peer is deleted\n"
	 "\t--ip2nets: specify a range of nids per peer"},
	{"show", jt_show_peer, 0, "show peer information\n"
	 "\t--nid: NID of peer to filter on.\n"
	 "\t--verbose: display detailed output per peer."
		       " Optional argument of '2' outputs more stats\n"},
	{"list", jt_list_peer, 0, "list all peers\n"},
	{"set", jt_set_peer_ni_value, 0, "set peer ni specific parameter\n"
	 "\t--nid: Peer NI NID to set the\n"
	 "\t--health: specify health value to set\n"
	 "\t--all: set all peer_nis values to the one specified\n"},
	{ 0, 0, 0, NULL }
};

command_t udsp_cmds[] = {
	{"add", jt_add_udsp, 0, "add a udsp\n"
	 "\t--src: ip2nets syntax specifying the local NID to match\n"
	 "\t--dst: ip2nets syntax specifying the remote NID to match\n"
	 "\t--rte: ip2nets syntax specifying the router NID to match\n"
	 "\t--priority: priority value (0 - highest priority)\n"
	 "\t--idx: index of where to insert the rule.\n"
	 "\t       By default, appends to the end of the rule list.\n"},
	{"del", jt_del_udsp, 0, "delete a udsp\n"
	"\t--idx: index of the Policy.\n"},
	{"show", jt_show_udsp, 0, "show udsps\n"
	 "\t --idx: index of the policy to show.\n"},
	{ 0, 0, 0, NULL }
};

static int jt_calc_service_id(int argc, char **argv)
{
	int rc;
	__u64 service_id;

	rc = lustre_lnet_calc_service_id(&service_id);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		return rc;

	/*
	 * cYAML currently doesn't support printing hex values.
	 * Therefore just print it locally here
	 */
	printf("service id:\n    value: 0x%jx\n", (uintmax_t)service_id);

	return rc;
}

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

	if (!number)
		return -1;

	*value = strtol(number,  &end, 0);
	if (end != NULL && *end != 0)
		return -1;

	return 0;
}

static int check_cmd(const command_t *cmd_list, const char *cmd,
		     const char *sub_cmd, const int min_args,
		     int argc, char **argv)
{
	int opt;
	int rc = 0;
	optind = 0;
	opterr = 0;

	const char *const short_options = "h";
	static const struct option long_options[] = {
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL }
	};

	if (argc < min_args) {
		print_help(cmd_list, cmd, sub_cmd);
		rc = -1;
		goto out;
	} else if (argc > 2) {
		return 0;
	}

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_help(cmd_list, cmd, sub_cmd);
			rc = 1;
			break;
		default:
			rc = 0;
			break;
		}
	}

out:
	opterr = 1;
	optind = 0;
	return rc;
}

static int jt_set_response_tracking(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "response_tracking", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse response_tracking value",
				  &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_response_tracking(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_recovery_limit(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "recovery_limit", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse recovery_limit value",
				  &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_recovery_limit(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_max_intf(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "max_interfaces", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse max_interfaces value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_max_intf(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_numa(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "numa_range", 2, argc, argv);
	if (rc)
		return rc;

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

static int jt_set_recov_intrv(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "recovery_interval", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse recovery interval value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_recov_intrv(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_rtr_sensitivity(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "router_sensitivity", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse router sensitivity value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_rtr_sensitivity(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_hsensitivity(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "health_sensitivity", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse health sensitivity value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_hsensitivity(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_transaction_to(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "transaction_timeout", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse transaction timeout value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_transaction_to(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_retry_count(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "retry_count", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse retry_count value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_retry_count(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_discovery(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "discovery", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse discovery value", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_discovery(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_drop_asym_route(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "drop_asym_route", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse drop_asym_route value",
				  &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_drop_asym_route(value, -1, &err_rc);
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

	rc = check_cmd(set_cmds, "set", "tiny_buffers", 2, argc, argv);
	if (rc)
		return rc;

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

	rc = check_cmd(set_cmds, "set", "small_buffers", 2, argc, argv);
	if (rc)
		return rc;

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

	rc = check_cmd(set_cmds, "set", "large_buffers", 2, argc, argv);
	if (rc)
		return rc;

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

	rc = check_cmd(set_cmds, "set", "routing", 2, argc, argv);
	if (rc)
		return rc;

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

	const char *const short_options = "a";
	static const struct option long_options[] = {
		{ .name = "all",  .has_arg = no_argument, .val = 'a' },
		{ .name = NULL }
	};

	rc = check_cmd(lnet_cmds, "lnet", "configure", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			load_mod_params = true;
			break;
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

	rc = check_cmd(lnet_cmds, "lnet", "unconfigure", 0, argc, argv);
	if (rc)
		return rc;

	rc = lustre_lnet_config_ni_system(LNET_UNCONFIGURE, 0, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}
static int jt_add_route(int argc, char **argv)
{
	char *network = NULL, *gateway = NULL;
	long int hop = -1, prio = -1, sen = -1;
	struct cYAML *err_rc = NULL;
	int rc, opt;

	const char *const short_options = "n:g:c:p:";
	static const struct option long_options[] = {
	{ .name = "net",       .has_arg = required_argument, .val = 'n' },
	{ .name = "gateway",   .has_arg = required_argument, .val = 'g' },
	{ .name = "hop-count", .has_arg = required_argument, .val = 'c' },
	{ .name = "priority",  .has_arg = required_argument, .val = 'p' },
	{ .name = "health_sensitivity",  .has_arg = required_argument, .val = 's' },
	{ .name = NULL } };

	rc = check_cmd(route_cmds, "route", "add", 0, argc, argv);
	if (rc)
		return rc;

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
		case 's':
			rc = parse_long(optarg, &sen);
			if (rc != 0) {
				/* ingore option */
				sen = -1;
				continue;
			}
			break;

		case '?':
			print_help(route_cmds, "route", "add");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_config_route(network, gateway, hop, prio, sen, -1,
				      &err_rc);

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

	const char *const short_options = "n:i:p:t:c:b:r:s:";
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
	{ .name = NULL } };

	rc = check_cmd(net_cmds, "net", "add", 0, argc, argv);
	if (rc)
		return rc;

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
		case '?':
			print_help(net_cmds, "net", "add");
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

	const char *const short_options = "n:g:";
	static const struct option long_options[] = {
		{ .name = "net",     .has_arg = required_argument, .val = 'n' },
		{ .name = "gateway", .has_arg = required_argument, .val = 'g' },
		{ .name = NULL } };

	rc = check_cmd(route_cmds, "route", "del", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			network = optarg;
			break;
		case 'g':
			gateway = optarg;
			break;
		case '?':
			print_help(route_cmds, "route", "del");
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

	const char *const short_options = "n:i:";
	static const struct option long_options[] = {
	{ .name = "net",	.has_arg = required_argument,	.val = 'n' },
	{ .name = "if",		.has_arg = required_argument,	.val = 'i' },
	{ .name = NULL } };

	rc = check_cmd(net_cmds, "net", "del", 0, argc, argv);
	if (rc)
		return rc;

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
		case '?':
			print_help(net_cmds, "net", "del");
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

	const char *const short_options = "n:g:h:p:v";
	static const struct option long_options[] = {
	{ .name = "net",       .has_arg = required_argument, .val = 'n' },
	{ .name = "gateway",   .has_arg = required_argument, .val = 'g' },
	{ .name = "hop-count", .has_arg = required_argument, .val = 'c' },
	{ .name = "priority",  .has_arg = required_argument, .val = 'p' },
	{ .name = "verbose",   .has_arg = no_argument,	     .val = 'v' },
	{ .name = NULL } };

	rc = check_cmd(route_cmds, "route", "show", 0, argc, argv);
	if (rc)
		return rc;

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
		case '?':
			print_help(route_cmds, "route", "show");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_route(network, gateway, hop, prio, detail, -1,
				    &show_rc, &err_rc, false);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int set_value_helper(int argc, char **argv,
			    int (*cb)(int, bool, char*, int, struct cYAML**))
{
	char *nid = NULL;
	long int healthv = -1;
	bool all = false;
	int rc, opt;
	struct cYAML *err_rc = NULL;

	const char *const short_options = "t:n:a";
	static const struct option long_options[] = {
		{ .name = "nid", .has_arg = required_argument, .val = 'n' },
		{ .name = "health", .has_arg = required_argument, .val = 't' },
		{ .name = "all", .has_arg = no_argument, .val = 'a' },
		{ .name = NULL } };

	rc = check_cmd(net_cmds, "net", "set", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nid = optarg;
			break;
		case 't':
			if (parse_long(optarg, &healthv) != 0)
				healthv = -1;
			break;
		case 'a':
			all = true;
			break;
		default:
			return 0;
		}
	}

	rc = cb(healthv, all, nid, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_set_ni_value(int argc, char **argv)
{
	return set_value_helper(argc, argv, lustre_lnet_config_ni_healthv);
}

static int jt_set_peer_ni_value(int argc, char **argv)
{
	return set_value_helper(argc, argv, lustre_lnet_config_peer_ni_healthv);
}

static int jt_show_recovery(int argc, char **argv)
{
	int rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;

	const char *const short_options = "lp";
	static const struct option long_options[] = {
		{ .name = "local", .has_arg = no_argument, .val = 'l' },
		{ .name = "peer", .has_arg = no_argument, .val = 'p' },
		{ .name = NULL } };

	rc = check_cmd(debug_cmds, "recovery", NULL, 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'l':
			rc = lustre_lnet_show_local_ni_recovq(-1, &show_rc, &err_rc);
			break;
		case 'p':
			rc = lustre_lnet_show_peer_ni_recovq(-1, &show_rc, &err_rc);
			break;
		default:
			return 0;
		}
	}

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
	int rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;
	long int detail = 0;

	const char *const short_options = "n:v";
	static const struct option long_options[] = {
		{ .name = "net",     .has_arg = required_argument, .val = 'n' },
		{ .name = "verbose", .has_arg = optional_argument, .val = 'v' },
		{ .name = NULL } };

	rc = check_cmd(net_cmds, "net", "show", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			network = optarg;
			break;
		case 'v':
			if ((!optarg) && (argv[optind] != NULL) &&
			    (argv[optind][0] != '-')) {
				if (parse_long(argv[optind++], &detail) != 0)
					detail = 1;
			} else {
				detail = 1;
			}
			break;
		case '?':
			print_help(net_cmds, "net", "show");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_net(network, (int) detail, -1, &show_rc, &err_rc,
				  false);

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

	rc = check_cmd(routing_cmds, "routing", "show", 0, argc, argv);
	if (rc)
		return rc;

	rc = lustre_lnet_show_routing(-1, &show_rc, &err_rc, false);

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

	rc = check_cmd(stats_cmds, "stats", "show", 0, argc, argv);
	if (rc)
		return rc;

	rc = lustre_lnet_show_stats(-1, &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_show_udsp(int argc, char **argv)
{
	int idx = -1;
	int rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;

	const char *const short_options = "i:";
	static const struct option long_options[] = {
		{ .name = "idx", .has_arg = required_argument, .val = 'i' },
		{ .name = NULL }
	};

	rc = check_cmd(udsp_cmds, "udsp", "show", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			idx = atoi(optarg);
			break;
		case '?':
			print_help(net_cmds, "net", "show");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_udsp(idx, -1, &show_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_show_global(int argc, char **argv)
{
	int rc;
	struct cYAML *show_rc = NULL, *err_rc = NULL;

	rc = check_cmd(global_cmds, "global", "show", 0, argc, argv);
	if (rc)
		return rc;

	rc = lustre_lnet_show_numa_range(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_max_intf(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_discovery(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_drop_asym_route(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_retry_count(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_transaction_to(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_hsensitivity(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_recov_intrv(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_rtr_sensitivity(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_lnd_timeout(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_response_tracking(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	rc = lustre_lnet_show_recovery_limit(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		goto out;
	}

	if (show_rc)
		cYAML_print_tree(show_rc);

out:
	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_lnet(int argc, char **argv)
{
	int rc;

	rc = check_cmd(lnet_cmds, "lnet", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], lnet_cmds);
}

static int jt_route(int argc, char **argv)
{
	int rc;

	rc = check_cmd(route_cmds, "route", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], route_cmds);
}

static int jt_net(int argc, char **argv)
{
	int rc;

	rc = check_cmd(net_cmds, "net", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], net_cmds);
}

static int jt_routing(int argc, char **argv)
{
	int rc;

	rc = check_cmd(routing_cmds, "routing", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], routing_cmds);
}

static int jt_stats(int argc, char **argv)
{
	int rc;

	rc = check_cmd(stats_cmds, "stats", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], stats_cmds);
}

static int jt_debug(int argc, char **argv)
{
	int rc;

	rc = check_cmd(debug_cmds, "recovery", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], debug_cmds);
}

static int jt_global(int argc, char **argv)
{
	int rc;

	rc = check_cmd(global_cmds, "global", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], global_cmds);
}

static int jt_peers(int argc, char **argv)
{
	int rc;

	rc = check_cmd(peer_cmds, "peer", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], peer_cmds);
}

static int jt_set(int argc, char **argv)
{
	int rc;

	rc = check_cmd(set_cmds, "set", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], set_cmds);
}

static int jt_udsp(int argc, char **argv)
{
	int rc;

	rc = check_cmd(udsp_cmds, "udsp", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return Parser_execarg(argc - 1, &argv[1], udsp_cmds);
}

static int jt_import(int argc, char **argv)
{
	char *file = NULL;
	struct cYAML *err_rc = NULL;
	struct cYAML *show_rc = NULL;
	int rc = 0, return_rc = 0, opt, opt_found = 0;
	char cmd = 'a';

	const char *const short_options = "adseh";
	static const struct option long_options[] = {
		{ .name = "add",  .has_arg = no_argument, .val = 'a' },
		{ .name = "del",  .has_arg = no_argument, .val = 'd' },
		{ .name = "show", .has_arg = no_argument, .val = 's' },
		{ .name = "exec", .has_arg = no_argument, .val = 'e' },
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		opt_found = 1;
		switch (opt) {
		case 'a':
			cmd = opt;
			break;
		case 'd':
		case 's':
			cmd = opt;
			break;
		case 'e':
			cmd = opt;
			break;
		case 'h':
			printf("import FILE\n"
			       "import < FILE : import a file\n"
			       "\t--add: add configuration\n"
			       "\t--del: delete configuration\n"
			       "\t--show: show configuration\n"
			       "\t--exec: execute command\n"
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
		return_rc = lustre_yaml_exec(file, &show_rc, &err_rc);
		cYAML_print_tree(show_rc);
		cYAML_free_tree(show_rc);
		break;
	case 'd':
		rc = lustre_yaml_del(file, &err_rc);
		break;
	case 's':
		rc = lustre_yaml_show(file, &show_rc, &err_rc);
		cYAML_print_tree(show_rc);
		cYAML_free_tree(show_rc);
		break;
	case 'e':
		rc = lustre_yaml_exec(file, &show_rc, &err_rc);
		cYAML_print_tree(show_rc);
		cYAML_free_tree(show_rc);
		break;
	}

	if (rc || return_rc) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
	}

	return rc;
}

static int jt_export(int argc, char **argv)
{
	struct cYAML *show_rc = NULL;
	struct cYAML *err_rc = NULL;
	int rc;
	FILE *f = NULL;
	int opt;
	bool backup = false;
	char *file = NULL;

	const char *const short_options = "bh";
	static const struct option long_options[] = {
		{ .name = "backup", .has_arg = no_argument, .val = 'b' },
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			backup = true;
			break;
		case 'h':
		default:
			printf("export > FILE.yaml : export configuration\n"
			       "\t--backup: export only what's necessary for reconfig\n"
			       "\t--help: display this help\n");
			return 0;
		}
	}

	if (backup && argc >= 3)
		file = argv[2];
	else if (!backup && argc >= 2)
		file = argv[1];
	else
		f = stdout;

	if (file) {
		f = fopen(file, "w");
		if (f == NULL)
			return -1;
	}

	rc = lustre_lnet_show_net(NULL, 2, -1, &show_rc, &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_route(NULL, NULL, -1, -1, 1, -1, &show_rc,
				    &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_routing(-1, &show_rc, &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_peer(NULL, 2, -1, &show_rc, &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_numa_range(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_max_intf(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_discovery(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_drop_asym_route(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_retry_count(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_transaction_to(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_hsensitivity(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_recov_intrv(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_rtr_sensitivity(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_lnd_timeout(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_response_tracking(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_recovery_limit(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_udsp(-1, -1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	if (show_rc != NULL) {
		cYAML_print_tree2file(f, show_rc);
		cYAML_free_tree(show_rc);
	}

	if (argc >= 2)
		fclose(f);

	return 0;
}

static int jt_peer_nid_common(int argc, char **argv, int cmd)
{
	int rc = LUSTRE_CFG_RC_NO_ERR, opt;
	bool is_mr = true;
	char *prim_nid = NULL, *nidstr = NULL;
	char err_str[LNET_MAX_STR_LEN] = "Error";
	struct cYAML *err_rc = NULL;

	const char *const short_opts = "k:mn:";
	const struct option long_opts[] = {
	{ .name = "prim_nid",	.has_arg = required_argument,	.val = 'k' },
	{ .name = "non_mr",	.has_arg = no_argument,		.val = 'm' },
	{ .name = "nid",	.has_arg = required_argument,	.val = 'n' },
	{ .name = NULL } };

	rc = check_cmd(peer_cmds, "peer", "add", 2, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_opts,
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'k':
			prim_nid = optarg;
			break;
		case 'n':
			nidstr = optarg;
			break;
		case 'm':
			if (cmd == LNETCTL_DEL_CMD) {
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				snprintf(err_str, LNET_MAX_STR_LEN,
					 "Unrecognized option '-%c'", opt);
				goto build_error;
			}
			is_mr = false;
			break;
		case '?':
			print_help(peer_cmds, "peer",
				   cmd == LNETCTL_ADD_CMD ? "add" : "del");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_modify_peer(prim_nid, nidstr, is_mr, cmd,
				     -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		goto out;

build_error:
	cYAML_build_error(rc, -1, "peer",
			  cmd == LNETCTL_ADD_CMD ? "add" : "del",
			  err_str, &err_rc);

out:
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_add_peer_nid(int argc, char **argv)
{
	return jt_peer_nid_common(argc, argv, LNETCTL_ADD_CMD);
}

static int jt_del_peer_nid(int argc, char **argv)
{
	return jt_peer_nid_common(argc, argv, LNETCTL_DEL_CMD);
}

static int jt_show_peer(int argc, char **argv)
{
	char *nid = NULL;
	int rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;
	long int detail = 0;

	const char *const short_opts = "hn:v::";
	const struct option long_opts[] = {
	{ .name = "help",	.has_arg = no_argument,		.val = 'h' },
	{ .name = "nid",	.has_arg = required_argument,	.val = 'n' },
	{ .name = "verbose",	.has_arg = optional_argument,	.val = 'v' },
	{ .name = NULL } };

	rc = check_cmd(peer_cmds, "peer", "show", 1, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_opts,
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nid = optarg;
			break;
		case 'v':
			if ((!optarg) && (argv[optind] != NULL) &&
			    (argv[optind][0] != '-')) {
				if (parse_long(argv[optind++], &detail) != 0)
					detail = 1;
			} else {
				detail = 1;
			}
			break;
		case '?':
			print_help(peer_cmds, "peer", "show");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_peer(nid, (int) detail, -1, &show_rc, &err_rc,
				   false);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_list_peer(int argc, char **argv)
{
	int rc;
	struct cYAML *err_rc = NULL, *list_rc = NULL;

	rc = check_cmd(peer_cmds, "peer", "list", 0, argc, argv);
	if (rc)
		return rc;

	rc = lustre_lnet_list_peer(-1, &list_rc, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (list_rc)
		cYAML_print_tree(list_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(list_rc);

	return rc;
}

static int jt_ping(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	struct cYAML *show_rc = NULL;
	int timeout = 1000;
	int rc = 0, opt;

	const char *const short_options = "ht:";
	const struct option long_options[] = {
	{ .name = "help",	.has_arg = no_argument,		.val = 'h' },
	{ .name = "timeout",	.has_arg = required_argument,	.val = 't' },
	{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 't':
			timeout = 1000 * atol(optarg);
			break;
		case 'h':
			printf("ping nid[,nid,...]\n"
			       "\t --timeout: ping timeout\n"
			       "\t --help: display this help\n");
			return 0;
		default:
			return 0;
		}
	}

	for (; optind < argc; optind++)
		rc = lustre_lnet_ping_nid(argv[optind], timeout, -1, &show_rc, &err_rc);

	if (show_rc)
		cYAML_print_tree(show_rc);

	if (err_rc)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_discover(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	struct cYAML *show_rc = NULL;
	int force = 0;
	int rc = 0, opt;

	const char *const short_options = "fh";
	const struct option long_options[] = {
		{ .name = "force",	.has_arg = no_argument,	.val = 'f' },
		{ .name = "help",	.has_arg = no_argument,	.val = 'h' },
		{ .name = NULL } };

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'f':
			force = 1;
			break;
		case 'h':
			printf("discover nid[,nid,...]\n"
			       "\t --force: force discovery\n"
			       "\t --help: display this help\n");
			return 0;
		default:
			return 0;
		}
	}

	for (; optind < argc; optind++)
		rc = lustre_lnet_discover_nid(argv[optind], force, -1, &show_rc,
					      &err_rc);

	if (show_rc)
		cYAML_print_tree(show_rc);

	if (err_rc)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_add_udsp(int argc, char **argv)
{
	char *src = NULL, *dst = NULL, *rte = NULL;
	struct cYAML *err_rc = NULL;
	union lnet_udsp_action udsp_action;
	long int idx = -1, priority = -1;
	int opt, rc = 0;
	char *action_type = "pref";

	const char *const short_options = "s:d:r:p:i:";
	static const struct option long_options[] = {
	{ .name = "src",	 .has_arg = required_argument, .val = 's' },
	{ .name = "dst",	 .has_arg = required_argument, .val = 'd' },
	{ .name = "rte",	 .has_arg = required_argument, .val = 'r' },
	{ .name = "priority",	 .has_arg = required_argument, .val = 'p' },
	{ .name = "idx",	 .has_arg = required_argument, .val = 'i' },
	{ .name = NULL } };

	rc = check_cmd(udsp_cmds, "udsp", "add", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 's':
			src = optarg;
			break;
		case 'd':
			dst = optarg;
			break;
		case 'r':
			rte = optarg;
			break;
		case 'p':
			rc = parse_long(optarg, &priority);
			if (rc != 0)
				priority = -1;
			action_type = "priority";
			udsp_action.udsp_priority = priority;
			break;
		case 'i':
			rc = parse_long(optarg, &idx);
			if (rc != 0)
				idx = 0;
			break;
		case '?':
			print_help(udsp_cmds, "udsp", "add");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_add_udsp(src, dst, rte, action_type, &udsp_action,
				  idx, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_del_udsp(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	long int idx = 0;
	int opt, rc = 0;

	const char *const short_options = "i:";
	static const struct option long_options[] = {
	{ .name = "idx",	.has_arg = required_argument, .val = 'i' },
	{ .name = NULL } };

	rc = check_cmd(udsp_cmds, "udsp", "del", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			rc = parse_long(optarg, &idx);
			if (rc != 0)
				idx = 0;
			break;
		case '?':
			print_help(udsp_cmds, "udsp", "add");
		default:
			return 0;
		}
	}

	rc = lustre_lnet_del_udsp(idx, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int lnetctl_list_commands(int argc, char **argv)
{
	char buffer[81] = ""; /* 80 printable chars + terminating NUL */

	Parser_list_commands(cmd_list, buffer, sizeof(buffer), NULL, 0, 4);

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

	Parser_init("lnetctl > ", cmd_list);
	if (argc > 1) {
		rc = Parser_execarg(argc - 1, &argv[1], cmd_list);
		goto errorout;
	}

	Parser_commands();

errorout:
	return rc;
}
