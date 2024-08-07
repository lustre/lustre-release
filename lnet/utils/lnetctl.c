// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (c) 2014, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Amir Shehata <amir.shehata@intel.com>
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/parser.h>
#include "lnetconfig/cyaml.h"
#include "lnetconfig/liblnetconfig.h"

#define LNET_CONFIGURE		true
#define LNET_UNCONFIGURE	false

#ifndef NLM_F_DUMP_FILTERED
#define NLM_F_DUMP_FILTERED    0x20
#endif

static int jt_config_lnet(int argc, char **argv);
static int jt_unconfig_lnet(int argc, char **argv);
static int jt_add_route(int argc, char **argv);
static int jt_add_ni(int argc, char **argv);
static int jt_add_fault(int argc, char **argv);
static int jt_set_routing(int argc, char **argv);
static int jt_del_route(int argc, char **argv);
static int jt_del_ni(int argc, char **argv);
static int jt_del_fault(int argc, char **argv);
static int jt_show_route(int argc, char **argv);
static int jt_show_net(int argc, char **argv);
static int jt_show_routing(int argc, char **argv);
static int jt_show_stats(int argc, char **argv);
static int jt_show_peer(int argc, char **argv);
static int jt_show_recovery(int argc, char **argv);
static int jt_show_global(int argc, char **argv);
static int jt_show_udsp(int argc, char **argv);
static int jt_show_fault(int argc, char **argv);
static int jt_set_tiny(int argc, char **argv);
static int jt_set_small(int argc, char **argv);
static int jt_set_large(int argc, char **argv);
static int jt_set_numa(int argc, char **argv);
static int jt_set_retry_count(int argc, char **argv);
static int jt_set_transaction_to(int argc, char **argv);
static int jt_set_recov_intrv(int argc, char **argv);
static int jt_set_rtr_sensitivity(int argc, char **argv);
static int jt_set_hsensitivity(int argc, char **argv);
static int jt_set_max_recovery_ping_interval(int argc, char **argv);
static int jt_reset_stats(int argc, char **argv);
static int jt_reset_fault(int argc, char **argv);
static int jt_add_peer_nid(int argc, char **argv);
static int jt_del_peer_nid(int argc, char **argv);
static int jt_set_max_intf(int argc, char **argv);
static int jt_set_discovery(int argc, char **argv);
static int jt_set_drop_asym_route(int argc, char **argv);
static int jt_list_peer(int argc, char **argv);
static int jt_add_udsp(int argc, char **argv);
static int jt_del_udsp(int argc, char **argv);
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
static int jt_fault(int argc, char **argv);
static int jt_setup_mrrouting(int argc, char **argv);
static int jt_setup_sysctl(int argc, char **argv);
static int jt_calc_cpt_of_nid(int argc, char **argv);
static int jt_show_peer_debug_info(int argc, char **argv);

command_t cmd_list[] = {
	{"lnet", jt_lnet, 0, "lnet {configure | unconfigure} [--all|--large]"},
	{"route", jt_route, 0, "route {add | del | show | help}"},
	{"net", jt_net, 0, "net {add | del | show | set | help}"},
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
	{"debug", jt_debug, 0, "debug {recovery {local | peer} | peer}"},
	{"global", jt_global, 0, "global {show | help}"},
	{"peer", jt_peers, 0, "peer {add | del | show | list | set | help}"},
	{"ping", jt_ping, 0, "ping nid,[nid,...]"},
	{"discover", jt_discover, 0, "discover nid[,nid,...]"},
	{"service-id", jt_calc_service_id, 0, "Calculate IB Lustre service ID\n"},
	{"udsp", jt_udsp, 0, "udsp {add | del | help}"},
	{"fault", jt_fault, 0, "udsp {show | help}"},
	{"setup-mrrouting", jt_setup_mrrouting, 0,
	 "setup linux routing tables\n"},
	{"setup-sysctl", jt_setup_sysctl, 0,
	 "setup linux sysctl parameter for large systems\n"},
	{"cpt-of-nid", jt_calc_cpt_of_nid, 0,
	 "Calculate the CPTs associated with NIDs\n"
	 " usage:\n\tlnetctl cpt-of-nid nid[ nid ...]\n"},
	{ 0, 0, 0, NULL }
};

command_t lnet_cmds[] = {
	{"configure", jt_config_lnet, 0, "configure lnet\n"
	 "\t--all: load NI configuration from module parameters\n"
	 "\t--large: start LNet with large NIDs\n"},
	{"unconfigure", jt_unconfig_lnet, 0, "unconfigure lnet\n"},
	{ 0, 0, 0, NULL }
};

command_t route_cmds[] = {
	{"add", jt_add_route, 0, "add a route\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp)\n"
	 "\t--hop|hop-count: number to final destination (1 <= hops <= 255)\n"
	 "\t--priority: priority of route (0 - highest prio\n"
	 "\t--health_sensitivity: gateway health sensitivity (>= 1)\n"},
	{"del", jt_del_route, 0, "delete a route\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp)\n"},
	{"show", jt_show_route, 0, "show routes\n"
	 "\t--net: net name (e.g. tcp0) to filter on\n"
	 "\t--gateway: gateway nid (e.g. 10.1.1.2@tcp) to filter on\n"
	 "\t--hop|hop-count: number to final destination (1 <= hops <= 255) to filter on\n"
	 "\t--priority: priority of route (0 - highest prio to filter on\n"
	 "\t--verbose: display detailed output per route\n"},
	{ 0, 0, 0, NULL }
};

command_t net_cmds[] = {
	{"add", jt_add_ni, 0, "add a network\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--if: physical interface (e.g. eth0)\n"
	 "\t--nid: bring up NI based on the address of the specified LNet NID\n"
	 "\t--ip2net: specify networks based on IP address patterns\n"
	 "\t--peer-timeout: time to wait before declaring a peer dead\n"
	 "\t--peer-credits: define the max number of inflight messages\n"
	 "\t--peer-buffer-credits: the number of buffer credits per peer\n"
	 "\t--credits: Network Interface credits\n"
	 "\t--cpt: CPU Partitions configured net uses (e.g. [0,1]\n"
	 "\t--conns-per-peer: number of connections per peer\n"
	 "\t--skip-mr-route-setup: do not add linux route for the ni\n"
	 "\t--auth-key: Network authorization key (kfilnd only)\n"
	 "\t--traffic-class: Traffic class (kfilnd only)\n"
	 "\t--tos: IP's Type of Service\n"},
	{"del", jt_del_ni, 0, "delete a network\n"
	 "\t--net: net name (e.g. tcp0)\n"
	 "\t--nid: shutdown NI based on the address of the specified LNet NID\n"
	 "\t--if: physical interface (e.g. eth0)\n"},
	{"show", jt_show_net, 0, "show networks\n"
	 "\t--net: net name (e.g. tcp0) to filter on\n"
	 "\t--verbose: display detailed output per network."
		       " Optional argument of '2' outputs more stats\n"},
	{"set", jt_set_ni_value, 0, "set local NI specific parameter\n"
	 "\t--nid: NI NID to set the\n"
	 "\t--health: specify health value to set\n"
	 "\t--conns-per-peer: number of connections per peer\n"
	 "\t--all: set all NIs value to the one specified\n"},
	{ 0, 0, 0, NULL }
};

command_t routing_cmds[] = {
	{"show", jt_show_routing, 0, "show routing information\n"},
	{ 0, 0, 0, NULL }
};

command_t stats_cmds[] = {
	{"show", jt_show_stats, 0, "show LNET statistics\n"},
	{"reset", jt_reset_stats, 0, "reset LNET statistics\n"},
	{ 0, 0, 0, NULL }
};

command_t debug_cmds[] = {
	{"recovery", jt_show_recovery, 0, "list recovery queues\n"
		"\t--local : list local recovery queue\n"
		"\t--peer : list peer recovery queue\n"},
	{"peer", jt_show_peer_debug_info, 0, "show peer debug info\n"
		"\t--nid: peer's NID\n"},
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
	{"max_recovery_ping_interval", jt_set_max_recovery_ping_interval, 0,
	 "maximum recovery ping interval\n"
	 "\t>0 - maximum recovery ping interval in seconds\n"},
	{ 0, 0, 0, NULL }
};

command_t peer_cmds[] = {
	{"add", jt_add_peer_nid, 0, "add a peer NID\n"
	 "\t--prim_nid: Primary NID of the peer.\n"
	 "\t--nid: one or more peer NIDs\n"
	 "\t--non_mr: create this peer as not Multi-Rail capable\n"
	 "\t--ip2nets: specify a range of nids per peer\n"
	 "\t--lock_prim: lock primary nid\n"},
	{"del", jt_del_peer_nid, 0, "delete a peer NID\n"
	 "\t--prim_nid: Primary NID of the peer.\n"
	 "\t--nid: list of NIDs to remove. If none provided,\n"
	 "\t       peer is deleted\n"
	 "\t--ip2nets: specify a range of nids per peer\n"
	 "\t--force: force-delete locked primary NID\n"},
	{"show", jt_show_peer, 0, "show peer information\n"
	 "\t--nid: NID of peer to filter on.\n"
	 "\t--verbose: display detailed output per peer."
		       " Optional argument of '2' outputs more stats\n"},
	{"list", jt_list_peer, 0, "list all peers\n"},
	{"set", jt_set_peer_ni_value, 0, "set peer ni specific parameter\n"
	 "\t--nid: Peer NI NID to set the\n"
	 "\t--health: specify health value to set\n"
	 "\t--all: set all peer_nis values to the one specified\n"
	 "\t--state: set peer state (DANGEROUS: for test/debug only)"},
	{ 0, 0, 0, NULL }
};

command_t udsp_cmds[] = {
	{"add", jt_add_udsp, 0, "add a udsp\n"
	 "\t--src nid|net: ip2nets syntax specifying the local NID or network to match.\n"
	 "\t--dst nid:     ip2nets syntax specifying the remote NID to match.\n"
	 "\t--rte nid:     ip2nets syntax specifying the router NID to match.\n"
	 "\t--priority p:  Assign priority value p where p >= 0.\n"
	 "\t               Note: 0 is the highest priority.\n"
	 "\t--idx n:       Insert the rule in the n'th position on the list of rules.\n"
	 "\t               By default, rules are appended to the end of the rule list.\n"},
	{"del", jt_del_udsp, 0, "delete a udsp\n"
	 "\t--all:   Delete all rules.\n"
	 "\t--idx n: Delete the rule at index n.\n"},
	{"show", jt_show_udsp, 0, "show udsps\n"
	 "\t--idx n: Show the rule at at index n.\n"
	 "\t         By default, all rules are shown.\n"},
	{ 0, 0, 0, NULL }
};

command_t fault_cmds[] = {
	{"add", jt_add_fault, 0, "add LNet fault rule\n"
	 "\t--rule_type:   Add rules of type t.\n"
	 "\t--source nid:  Add rule entry with source NID.\n"
	 "\t--dest nid:	   Add rule entry with destination NID.\n"
	 "\t--rate:	   Rule entry rate.\n"
	 "\t--interval:    How long to run the rule.\n"
	 "\t--portal:	   Rule portal.\n"
	 "\t--message:	   Type of message <PUT|ACK|GET|REPLY>.\n"
	 "\t--health_error: Act on a specific health error (drop only).\n"
	 "\t--latency:	   Delay sending a message (delay only).\n"},
	{"del", jt_del_fault, 0, "delete LNet fault rule\n"
	 "\t--rule_type:   Delete all rules of type t.\n"
	 "\t--source nid:  Delete rule entry with source NID\n"
	 "\t--dest nid:	   Delete rule entry with destination NID\n"},
	{"reset", jt_reset_fault, 0, "reset_fault\n"
	 "\t--rule_type t: Reset the LNet rule t.\n"},
	{"show", jt_show_fault, 0, "show fault rules\n"
	 "\t--rule_type t: Show LNet fault rules of type t.\n"},
	{ 0, 0, 0, NULL }
};

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

static int jt_setup_mrrouting(int argc, char **argv)
{
	int rc;
	struct cYAML *err_rc = NULL;

	rc = lustre_lnet_setup_mrrouting(&err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int jt_setup_sysctl(int argc, char **argv)
{
	int rc;
	struct cYAML *err_rc = NULL;

	rc = lustre_lnet_setup_sysctl(&err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

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
		rc = LUSTRE_CFG_RC_BAD_PARAM;
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

static int jt_calc_service_id(int argc, char **argv)
{
	int rc;
	__u64 service_id;

	rc = lustre_lnet_calc_service_id(&service_id);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		return rc;

	/* cYAML currently doesn't support printing hex values.
	 * Therefore just print it locally here
	 */
	printf("service_id:\n    value: 0x%llx\n",
	       (unsigned long long)(service_id));

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

static int jt_reset_stats(int argc, char **argv)
{
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(stats_cmds, "stats", "reset", 0, argc, argv);
	if (rc)
		return rc;

	rc = lustre_lnet_reset_stats(-1, &err_rc);
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

static int jt_set_max_recovery_ping_interval(int argc, char **argv)
{
	long int value;
	int rc;
	struct cYAML *err_rc = NULL;

	rc = check_cmd(set_cmds, "set", "maximum recovery_interval", 2, argc, argv);
	if (rc)
		return rc;

	rc = parse_long(argv[1], &value);
	if (rc != 0) {
		cYAML_build_error(-1, -1, "parser", "set",
				  "cannot parse maximum recovery interval value",
				  &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		return -1;
	}

	rc = lustre_lnet_config_max_recovery_ping_interval(value, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static void yaml_lnet_print_error(int op, char *cmd, const char *errstr)
{
	char errcode[INT_STRING_LEN];
	yaml_emitter_t log;
	yaml_event_t event;
	const char *flag;
	int rc;

	snprintf(errcode, sizeof(errcode), "%d", errno);

	yaml_emitter_initialize(&log);
	yaml_emitter_set_indent(&log, LNET_DEFAULT_INDENT);
	yaml_emitter_set_output_file(&log, stderr);

	yaml_emitter_open(&log);
	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	if (strcmp(cmd, "lnet") == 0) {
		flag = "configure";
		goto skip_op;
	}

	switch (op) {
	case NLM_F_CREATE:
		flag = "add";
		break;
	case NLM_F_REPLACE:
		flag = "set";
		break;
	case 0:
		flag = "del";
		break;
	case -1:
		flag = "manage";
		break;
	case NLM_F_DUMP:
	default:
		flag = "show";
		break;
	}
skip_op:
	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)flag,
				     strlen(flag), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_sequence_start_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_SEQ_TAG,
					     1, YAML_ANY_SEQUENCE_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)cmd,
				     strlen(cmd),
				     1, 0, YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"",
				     strlen(""),
				     1, 0, YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"errno",
				     strlen("errno"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_INT_TAG,
				     (yaml_char_t *)errcode,
				     strlen(errcode), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;


	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"descr",
				     strlen("descr"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)errstr,
				     strlen(errstr), 1, 0,
				     YAML_DOUBLE_QUOTED_SCALAR_STYLE);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_sequence_end_event_initialize(&event);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_document_end_event_initialize(&event, 0);
	rc = yaml_emitter_emit(&log, &event);
	if (rc == 0)
		goto emitter_error;

	rc = yaml_emitter_close(&log);
emitter_error:
	if (rc == 0)
		yaml_emitter_log_error(&log, stdout);
	yaml_emitter_delete(&log);
}

static int yaml_lnet_cpt_of_nid_display(yaml_parser_t *reply)
{
	yaml_document_t results;
	yaml_emitter_t output;
	int rc;

	rc = yaml_parser_load(reply, &results);
	if (rc == 0) {
		yaml_lnet_print_error(NLM_F_DUMP, "cpt-of-nid",
				      yaml_parser_get_reader_error(reply));
		yaml_document_delete(&results);
		return -EINVAL;
	}

	rc = yaml_emitter_initialize(&output);
	if (rc == 1) {
		yaml_emitter_set_output_file(&output, stdout);

		rc = yaml_emitter_dump(&output, &results);
	}

	yaml_document_delete(&results);
	if (rc == 0) {
		yaml_emitter_log_error(&output, stderr);
		rc = -EINVAL;
	}
	yaml_emitter_delete(&output);

	return 1;
}

static int yaml_lnet_cpt_of_nid(int start, int end, char **nids)
{
	struct nl_sock *sk = NULL;
	yaml_emitter_t request;
	yaml_parser_t reply;
	yaml_event_t event;
	int i, rc;

	/* Create Netlink emitter to send request to kernel */
	sk = nl_socket_alloc();
	if (!sk)
		return -EOPNOTSUPP;

	/* Setup parser to receive Netlink packets */
	rc = yaml_parser_initialize(&reply);
	if (rc == 0) {
		nl_socket_free(sk);
		return -EOPNOTSUPP;
	}

	rc = yaml_parser_set_input_netlink(&reply, sk, false);
	if (rc == 0)
		goto free_reply;

	/* Create Netlink emitter to send request to kernel */
	rc = yaml_emitter_initialize(&request);
	if (rc == 0)
		goto free_reply;

	rc = yaml_emitter_set_output_netlink(&request, sk, LNET_GENL_NAME,
					     LNET_GENL_VERSION,
					     LNET_CMD_CPT_OF_NID, NLM_F_DUMP);
	if (rc == 0)
		goto emitter_error;

	yaml_emitter_open(&request);
	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"cpt-of-nid",
				     strlen("cpt-of-nid"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"nids",
				     strlen("nids"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_sequence_start_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_SEQ_TAG,
					     1, YAML_FLOW_SEQUENCE_STYLE);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	for (i = start; i < end; i++) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)nids[i],
					     strlen(nids[i]), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto emitter_error;
	}

	yaml_sequence_end_event_initialize(&event);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_document_end_event_initialize(&event, 0);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto emitter_error;

	rc = yaml_emitter_close(&request);
emitter_error:
	if (rc == 0) {
		yaml_emitter_log_error(&request, stderr);
		rc = -EINVAL;
	} else {
		rc = yaml_lnet_cpt_of_nid_display(&reply);
	}
	yaml_emitter_delete(&request);
free_reply:
	if (rc == 0) {
		yaml_lnet_print_error(NLM_F_DUMP, "cpt-of-nid",
				      yaml_parser_get_reader_error(&reply));
		rc = -EINVAL;
	}

	yaml_parser_delete(&reply);
	nl_socket_free(sk);

	return rc == 1 ? 0 : rc;
}

static int jt_calc_cpt_of_nid(int argc, char **argv)
{
	int rc, opt;
	const char *const short_options = "h";
	static const struct option long_options[] = {
	{ .name = "help", .val = 'h' },
	{ .name = NULL } };

	rc = check_cmd(cmd_list, "", "cpt-of-nid", 2, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
		case '?':
			print_help(cmd_list, "", "cpt-of-nid");
		default:
			return 0;
		}
	}

	rc = yaml_lnet_cpt_of_nid(optind, argc, argv);
	if (rc == -EOPNOTSUPP)
		printf("Operation not supported\n");

	return rc;
}

static int jt_config_lnet(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	bool load_mod_params = false;
	int flags = NLM_F_CREATE;
	const char *msg = NULL;
	int rc, opt;
	const char *const short_options = "al";
	static const struct option long_options[] = {
		{ .name = "all",	.has_arg = no_argument, .val = 'a' },
		{ .name = "large",	.has_arg = no_argument, .val = 'l' },
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
		case 'l':
			flags |= NLM_F_APPEND;
			break;
		default:
			return 0;
		}
	}

	if (!load_mod_params)
		flags |= NLM_F_EXCL;

	rc = yaml_lnet_configure(flags, &msg);
	if (rc != -EOPNOTSUPP) {
		if (rc < 0) {
			char errstr[256];

			snprintf(errstr, sizeof(errstr),
				 "LNet configure error: %s", msg);
			yaml_lnet_print_error(flags, "lnet", errstr);
		}
		return rc;
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
	const char *msg = NULL;
	int rc;

	rc = check_cmd(lnet_cmds, "lnet", "unconfigure", 0, argc, argv);
	if (rc)
		return rc;

	rc = yaml_lnet_configure(0, &msg);
	if (rc != -EOPNOTSUPP) {
		if (rc < 0) {
			char errstr[256];

			snprintf(errstr, sizeof(errstr),
				 "LNet configure error: %s", msg);
			yaml_lnet_print_error(0, "lnet", errstr);
		}
		return rc;
	}

	rc = lustre_lnet_config_ni_system(LNET_UNCONFIGURE, 0, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int yaml_lnet_router_gateways(yaml_emitter_t *output, const char *nw,
				     const char *gw, int hops, int prio,
				     int sen)
{
	char num[INT_STRING_LEN];
	yaml_event_t event;
	int rc;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG, 1,
					    YAML_BLOCK_MAPPING_STYLE);
	rc = yaml_emitter_emit(output, &event);
	if (rc == 0)
		goto emitter_error;

	if (nw) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"net",
					     strlen("net"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)nw,
					     strlen(nw), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	if (gw) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"gateway",
					     strlen("gateway"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)gw,
					     strlen(gw), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	if (hops != -1) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"hop",
					     strlen("hop"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;

		snprintf(num, sizeof(num), "%d", hops);
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_INT_TAG,
					     (yaml_char_t *)num,
					     strlen(num), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	if (prio != -1) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"priority",
					     strlen("priority"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;

		snprintf(num, sizeof(num), "%d", prio);
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_INT_TAG,
					     (yaml_char_t *)num,
					     strlen(num), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	if (sen != -1) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"health_sensitivity",
					     strlen("health_sensitivity"),
					     1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;

		snprintf(num, sizeof(num), "%d", sen);
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_INT_TAG,
					     (yaml_char_t *)num,
					     strlen(num), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(output, &event);
emitter_error:
	return rc;
}

static int yaml_lnet_route(char *nw, char *gw, int hops, int prio, int sen,
			   int version, int flags, FILE *fp)
{
	struct nid_node head, *entry;
	struct nl_sock *sk = NULL;
	const char *msg = NULL;
	yaml_emitter_t output;
	yaml_parser_t reply;
	yaml_event_t event;
	int rc;

	if (!(flags & NLM_F_DUMP) && (!nw || !gw)) {
		fprintf(stdout, "missing mandatory parameters:'%s'\n",
			(!nw && !gw) ? "net , gateway" :
			!nw ? "net" : "gateway");
		return -EINVAL;
	}

	/* Create Netlink emitter to send request to kernel */
	sk = nl_socket_alloc();
	if (!sk)
		return -EOPNOTSUPP;

	/* Setup parser to receive Netlink packets */
	rc = yaml_parser_initialize(&reply);
	if (rc == 0) {
		nl_socket_free(sk);
		return -EOPNOTSUPP;
	}

	rc = yaml_parser_set_input_netlink(&reply, sk, false);
	if (rc == 0) {
		msg = yaml_parser_get_reader_error(&reply);
		goto free_reply;
	}

	/* Create Netlink emitter to send request to kernel */
	rc = yaml_emitter_initialize(&output);
	if (rc == 0) {
		msg = "failed to initialize emitter";
		goto free_reply;
	}

	rc = yaml_emitter_set_output_netlink(&output, sk, LNET_GENL_NAME,
					     version, LNET_CMD_ROUTES, flags);
	if (rc == 0)
		goto emitter_error;

	yaml_emitter_open(&output);
	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"route",
				     strlen("route"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	/* NLM_F_DUMP can have no arguments */
	if (nw || gw) {
		NL_INIT_LIST_HEAD(&head.children);
		nl_init_list_head(&head.list);
		if (gw) {
			rc = lustre_lnet_parse_nid_range(&head, gw, &msg);
			if (rc < 0) {
				lustre_lnet_free_list(&head);
				yaml_emitter_delete(&output);
				errno = rc;
				rc = 0;
				goto free_reply;
			}
		}

		yaml_sequence_start_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_SEQ_TAG,
						     1,
						     YAML_BLOCK_SEQUENCE_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		if (!nl_list_empty(&head.children)) {
			nl_list_for_each_entry(entry, &head.children, list) {
				const char *nid = entry->nidstr;

				rc = yaml_lnet_router_gateways(&output, nw, nid,
							       hops, prio, sen);
				if (rc == 0)
					goto emitter_error;
			}
		} else {
			rc = yaml_lnet_router_gateways(&output, nw, NULL, hops,
						       prio, sen);
			if (rc == 0)
				goto emitter_error;
		}

		yaml_sequence_end_event_initialize(&event);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
	} else {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"",
					     strlen(""), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_document_end_event_initialize(&event, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	rc = yaml_emitter_close(&output);
emitter_error:
	if (rc == 0) {
		yaml_emitter_log_error(&output, stderr);
		rc = -EINVAL;
	} else {
		yaml_document_t errmsg;

		rc = yaml_parser_load(&reply, &errmsg);
		if (rc == 1 && (flags & NLM_F_DUMP)) {
			yaml_emitter_t debug;

			rc = yaml_emitter_initialize(&debug);
			if (rc == 1) {
				yaml_emitter_set_indent(&debug,
							LNET_DEFAULT_INDENT);
				yaml_emitter_set_output_file(&debug, fp);
				rc = yaml_emitter_dump(&debug, &errmsg);
			}
			yaml_emitter_delete(&debug);
		} else {
			msg = yaml_parser_get_reader_error(&reply);
			/* If we didn't find any routes just be silent */
			if (msg && strcmp(msg, "No routes found") == 0)
				rc = 1;
		}
		yaml_document_delete(&errmsg);
	}
	yaml_emitter_delete(&output);
free_reply:
	if (rc == 0) {
		yaml_lnet_print_error(flags, "route", msg);
		rc = -EINVAL;
	}
	yaml_parser_delete(&reply);
	nl_socket_free(sk);

	return rc == 1 ? 0 : rc;
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
		{ .name = "hop",       .has_arg = required_argument, .val = 'c' },
		{ .name = "hop-count", .has_arg = required_argument, .val = 'c' },
		{ .name = "priority",  .has_arg = required_argument, .val = 'p' },
		{ .name = "health_sensitivity",  .has_arg = required_argument, .val = 's' },
		{ .name = NULL }
	};

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

	rc = yaml_lnet_route(network, gateway, hop, prio, sen,
			     LNET_GENL_VERSION, NLM_F_CREATE, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
	rc = lustre_lnet_config_route(network, gateway, hop, prio, sen, -1,
				      &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int yaml_add_ni_tunables(yaml_emitter_t *output,
				struct lnet_ioctl_config_lnd_tunables *tunables,
				struct lnet_dlc_network_descr *nw_descr)
{
	char num[INT_STRING_LEN];
	yaml_event_t event;
	int rc = 0;

	if (tunables->lt_cmn.lct_peer_timeout < 0 &&
	    tunables->lt_cmn.lct_peer_tx_credits <= 0 &&
	    tunables->lt_cmn.lct_peer_rtr_credits <= 0 &&
	    tunables->lt_cmn.lct_max_tx_credits <= 0)
		goto skip_general_settings;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"tunables",
				     strlen("tunables"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(output, &event);
	if (rc == 0)
		goto error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(output, &event);
	if (rc == 0)
		goto error;

	if (tunables->lt_cmn.lct_peer_timeout >= 0) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"peer_timeout",
					     strlen("peer_timeout"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;

		snprintf(num, sizeof(num), "%u",
			 tunables->lt_cmn.lct_peer_timeout);
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_INT_TAG,
					     (yaml_char_t *)num,
					     strlen(num), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;
	}

	if (tunables->lt_cmn.lct_peer_tx_credits > 0) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"peer_credits",
					     strlen("peer_credits"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;

		snprintf(num, sizeof(num), "%u",
			 tunables->lt_cmn.lct_peer_tx_credits);
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_INT_TAG,
					     (yaml_char_t *)num,
					     strlen(num), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;
	}

	if (tunables->lt_cmn.lct_peer_rtr_credits > 0) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"peer_buffer_credits",
					     strlen("peer_buffer_credits"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;

		snprintf(num, sizeof(num), "%u",
			 tunables->lt_cmn.lct_peer_rtr_credits);
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_INT_TAG,
					     (yaml_char_t *)num,
					     strlen(num), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;
	}

	if (tunables->lt_cmn.lct_max_tx_credits > 0) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"credits",
					     strlen("credits"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;

		snprintf(num, sizeof(num), "%u",
			 tunables->lt_cmn.lct_max_tx_credits);
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_INT_TAG,
					     (yaml_char_t *)num,
					     strlen(num), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;
	}

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(output, &event);
	if (rc == 0)
		goto error;

skip_general_settings:
	if (tunables->lt_tun.lnd_tun_u.lnd_sock.lnd_conns_per_peer > 0 ||
	    tunables->lt_tun.lnd_tun_u.lnd_sock.lnd_tos >= 0 ||
#ifdef HAVE_KFILND
	    tunables->lt_tun.lnd_tun_u.lnd_kfi.lnd_auth_key > 0 ||
	    tunables->lt_tun.lnd_tun_u.lnd_kfi.lnd_traffic_class_str[0] ||
#endif
	    tunables->lt_tun.lnd_tun_u.lnd_o2ib.lnd_conns_per_peer > 0 ||
	    tunables->lt_tun.lnd_tun_u.lnd_o2ib.lnd_tos >= 0) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"lnd tunables",
					     strlen("lnd tunables"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;

		yaml_mapping_start_event_initialize(&event, NULL,
						    (yaml_char_t *)YAML_MAP_TAG,
						    1, YAML_ANY_MAPPING_STYLE);
		rc = yaml_emitter_emit(output, &event);
		if (rc == 0)
			goto error;
#ifdef HAVE_KFILND
		if (tunables->lt_tun.lnd_tun_u.lnd_kfi.lnd_auth_key > 0) {
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"auth_key",
						     strlen("auth_key"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;

			snprintf(num, sizeof(num), "%u",
				 tunables->lt_tun.lnd_tun_u.lnd_kfi.lnd_auth_key);

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)num,
						     strlen(num), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;
		}

		if (tunables->lt_tun.lnd_tun_u.lnd_kfi.lnd_traffic_class_str[0]) {
			char *tc = &tunables->lt_tun.lnd_tun_u.lnd_kfi.lnd_traffic_class_str[0];

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"traffic_class",
						     strlen("traffic_class"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)tc,
						     strlen(tc), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);

			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;
		}
#endif
		if (tunables->lt_tun.lnd_tun_u.lnd_sock.lnd_conns_per_peer > 0 ||
		    tunables->lt_tun.lnd_tun_u.lnd_o2ib.lnd_conns_per_peer > 0) {
			int cpp = 0;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"conns_per_peer",
						     strlen("conns_per_peer"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;

			if (nw_descr->nw_id == LNET_NET_ANY)
				cpp = tunables->lt_tun.lnd_tun_u.lnd_sock.lnd_conns_per_peer;
			else if (LNET_NETTYP(nw_descr->nw_id) == SOCKLND)
				cpp = tunables->lt_tun.lnd_tun_u.lnd_sock.lnd_conns_per_peer;
			else if (LNET_NETTYP(nw_descr->nw_id) == O2IBLND)
				cpp = tunables->lt_tun.lnd_tun_u.lnd_o2ib.lnd_conns_per_peer;
			snprintf(num, sizeof(num), "%u", cpp);

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)num,
						     strlen(num), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;
		}

		if (tunables->lt_tun.lnd_tun_u.lnd_sock.lnd_tos >= 0 ||
		    tunables->lt_tun.lnd_tun_u.lnd_o2ib.lnd_tos >= 0) {
			int tos = 0;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"tos",
						     strlen("tos"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;

			if (LNET_NETTYP(nw_descr->nw_id) == SOCKLND)
				tos = tunables->lt_tun.lnd_tun_u.lnd_sock.lnd_tos;
			else if (LNET_NETTYP(nw_descr->nw_id) == O2IBLND)
				tos = tunables->lt_tun.lnd_tun_u.lnd_o2ib.lnd_tos;
			snprintf(num, sizeof(num), "%u", tos);

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)num,
						     strlen(num), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(output, &event);
			if (rc == 0)
				goto error;
		}

		yaml_mapping_end_event_initialize(&event);
		rc = yaml_emitter_emit(output, &event);
	}
error:
	return rc;
}

static int yaml_lnet_config_ni(char *net_id, char *ip2net,
			       struct lnet_dlc_network_descr *nw_descr,
			       struct lnet_ioctl_config_lnd_tunables *tunables,
			       int healthv, struct cfs_expr_list *global_cpts,
			       int version, int flags, FILE *fp)
{
	struct lnet_dlc_intf_descr *intf;
	struct nl_sock *sk = NULL;
	const char *msg = NULL;
	yaml_emitter_t output;
	yaml_parser_t reply;
	yaml_event_t event;
	int rc;

	if (!(flags & NLM_F_DUMP) && !ip2net && (!nw_descr || nw_descr->nw_id == 0)) {
		fprintf(stdout, "missing mandatory parameters in NI config: '%s'\n",
			(!nw_descr) ? "network , interface" :
			(nw_descr->nw_id == 0) ? "network" : "interface");
		return -EINVAL;
	}

	if ((flags == NLM_F_CREATE) && !ip2net && list_empty(&nw_descr->nw_intflist)) {
		fprintf(stdout, "creating a local NI needs at least one interface\n");
		return -EINVAL;
	}

	if ((flags == NLM_F_REPLACE) && list_empty(&nw_descr->nw_intflist)) {
		fprintf(stdout, "updating a local NI needs at least one address\n");
		return -EINVAL;
	}

	/* Create Netlink emitter to send request to kernel */
	sk = nl_socket_alloc();
	if (!sk)
		return -EOPNOTSUPP;

	/* Setup parser to receive Netlink packets */
	rc = yaml_parser_initialize(&reply);
	if (rc == 0) {
		nl_socket_free(sk);
		return -EOPNOTSUPP;
	}

	rc = yaml_parser_set_input_netlink(&reply, sk, false);
	if (rc == 0) {
		msg = yaml_parser_get_reader_error(&reply);
		goto free_reply;
	}

	/* Create Netlink emitter to send request to kernel */
	rc = yaml_emitter_initialize(&output);
	if (rc == 0) {
		msg = "failed to initialize emitter";
		goto free_reply;
	}

	rc = yaml_emitter_set_output_netlink(&output, sk, LNET_GENL_NAME,
					     version, LNET_CMD_NETS, flags);
	if (rc == 0)
		goto emitter_error;

	yaml_emitter_open(&output);
	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"net",
				     strlen("net"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	if (net_id || ip2net) {
		char *key = net_id ? "net type" : "ip2net";
		char *value = net_id ? net_id : ip2net;

		yaml_sequence_start_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_SEQ_TAG,
						     1, YAML_ANY_SEQUENCE_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_mapping_start_event_initialize(&event, NULL,
						    (yaml_char_t *)YAML_MAP_TAG,
						    1, YAML_ANY_MAPPING_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)key,
					     strlen(key),
					     1, 0, YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)value,
					     strlen(value), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
	} else {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"",
					     strlen(""), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		goto no_net_id;
	}

	if (!nw_descr || list_empty(&nw_descr->nw_intflist))
		goto skip_intf;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"local NI(s)",
				     strlen("local NI(s)"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_sequence_start_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_SEQ_TAG,
					     1, YAML_ANY_SEQUENCE_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	list_for_each_entry(intf, &nw_descr->nw_intflist,
			    intf_on_network) {
		yaml_mapping_start_event_initialize(&event, NULL,
						    (yaml_char_t *)YAML_MAP_TAG,
						    1, YAML_ANY_MAPPING_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		/* Use NI addresses instead of interface */
		if (strchr(intf->intf_name, '@') ||
		    (strcmp(intf->intf_name, "<?>") == 0 &&
-                    flags == NLM_F_REPLACE)) {
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"nid",
						     strlen("nid"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)intf->intf_name,
						     strlen(intf->intf_name), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		} else {
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"interfaces",
						     strlen("interfaces"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_mapping_start_event_initialize(&event, NULL,
							    (yaml_char_t *)YAML_MAP_TAG,
							    1, YAML_ANY_MAPPING_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"0",
						     strlen("0"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)intf->intf_name,
						     strlen(intf->intf_name), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_mapping_end_event_initialize(&event);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		}

		if (tunables) {
			rc = yaml_add_ni_tunables(&output, tunables, nw_descr);
			if (rc == 0)
				goto emitter_error;
		}

		if (flags == NLM_F_REPLACE && healthv > -1) {
			char health[INT_STRING_LEN];

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"health stats",
						     strlen("health stats"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			/* Setup all mappings for data related to the 'health stats' */
			yaml_mapping_start_event_initialize(&event, NULL,
							    (yaml_char_t *)YAML_MAP_TAG,
							    1, YAML_BLOCK_MAPPING_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"health value",
						     strlen("health value"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			snprintf(health, sizeof(health), "%d", healthv);
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)health,
						     strlen(health), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_mapping_end_event_initialize(&event);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		}

		if (global_cpts) {
			__u32 *cpt_array;
			int count, i;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"CPT",
						     strlen("CPT"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_sequence_start_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_SEQ_TAG,
							     1,
							     YAML_FLOW_SEQUENCE_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			count = cfs_expr_list_values(global_cpts,
						     LNET_MAX_SHOW_NUM_CPT,
						     &cpt_array);
			for (i = 0; i < count; i++) {
				char core[INT_STRING_LEN];

				snprintf(core, sizeof(core), "%u", cpt_array[i]);
				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)core,
							     strlen(core), 1, 0,
							     YAML_PLAIN_SCALAR_STYLE);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;
			}

			yaml_sequence_end_event_initialize(&event);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			cfs_expr_list_free(global_cpts);
			free(cpt_array);
		}

		yaml_mapping_end_event_initialize(&event);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	yaml_sequence_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;
skip_intf:
	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_sequence_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;
no_net_id:
	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_document_end_event_initialize(&event, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	rc = yaml_emitter_close(&output);
emitter_error:
	if (rc == 0) {
		yaml_emitter_log_error(&output, stderr);
		rc = -EINVAL;
	} else {
		yaml_document_t errmsg;

		rc = yaml_parser_load(&reply, &errmsg);
		if (rc == 1 && (flags & NLM_F_DUMP)) {
			yaml_emitter_t debug;

			rc = yaml_emitter_initialize(&debug);
			if (rc == 1) {
				yaml_emitter_set_indent(&debug,
							LNET_DEFAULT_INDENT);
				yaml_emitter_set_output_file(&debug, fp);
				rc = yaml_emitter_dump(&debug, &errmsg);
			}
			yaml_emitter_delete(&debug);
		} else {
			msg = yaml_parser_get_reader_error(&reply);
		}
		yaml_document_delete(&errmsg);
	}
	yaml_emitter_delete(&output);
free_reply:
	if (rc == 0) {
		yaml_lnet_print_error(flags, "net", msg);
		rc = -EINVAL;
	}
	yaml_parser_delete(&reply);
	nl_socket_free(sk);

	return rc == 1 ? 0 : rc;
}

static int jt_add_ni(int argc, char **argv)
{
	char *ip2net = NULL;
	long int pto = -1, pc = -1, pbc = -1, cre = -1, cpp = -1, auth_key = -1;
	char *traffic_class = NULL;
	long int tos = -1;
	struct cYAML *err_rc = NULL;
	int rc, opt, cpt_rc = -1;
	struct lnet_dlc_network_descr nw_descr;
	struct cfs_expr_list *global_cpts = NULL;
	struct lnet_ioctl_config_lnd_tunables tunables;
	bool found = false;
	bool skip_mr_route_setup = false;
	const char *const short_options = "a:b:c:i:k:m:n:p:r:s:t:T:";
	static const struct option long_options[] = {
	{ .name = "auth-key",	  .has_arg = required_argument, .val = 'a' },
	{ .name = "peer-buffer-credits",
				  .has_arg = required_argument, .val = 'b' },
	{ .name = "peer-credits", .has_arg = required_argument, .val = 'c' },
	{ .name = "if",		  .has_arg = required_argument, .val = 'i' },
	{ .name = "skip-mr-route-setup",
				  .has_arg = no_argument, .val = 'k' },
	{ .name = "conns-per-peer",
				  .has_arg = required_argument, .val = 'm' },
	{ .name = "net",	  .has_arg = required_argument, .val = 'n' },
	{ .name = "nid",	  .has_arg = required_argument, .val = 'N' },
	{ .name = "ip2net",	  .has_arg = required_argument, .val = 'p' },
	{ .name = "credits",	  .has_arg = required_argument, .val = 'r' },
	{ .name = "cpt",	  .has_arg = required_argument, .val = 's' },
	{ .name = "peer-timeout", .has_arg = required_argument, .val = 't' },
	{ .name = "traffic-class", .has_arg = required_argument, .val = 'T' },
	{ .name = "tos", .has_arg = required_argument, .val = 'S' },
	{ .name = NULL } };
	bool nid_request = false;
	char *net_id = NULL;

	memset(&tunables, 0, sizeof(tunables));
	lustre_lnet_init_nw_descr(&nw_descr);

	rc = check_cmd(net_cmds, "net", "add", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			rc = parse_long(optarg, &auth_key);
			if (rc != 0) {
				/* ignore option */
				auth_key = -1;
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
		case 'c':
			rc = parse_long(optarg, &pc);
			if (rc != 0) {
				/* ignore option */
				pc = -1;
				continue;
			}
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
		case 'k':
			skip_mr_route_setup = true;
			break;
		case 'm':
			rc = parse_long(optarg, &cpp);
			if (rc != 0) {
				/* ignore option */
				cpp = -1;
				continue;
			}
			break;

		case 'n':
			nw_descr.nw_id = libcfs_str2net(optarg);
			net_id = optarg;
			break;
		case 'N':
			rc = lustre_lnet_parse_interfaces(optarg, &nw_descr);
			if (rc != 0) {
				cYAML_build_error(-1, -1, "ni", "add",
						"bad NID list",
						&err_rc);
				goto failed;
			}
			nid_request = true;
			break;
		case 'p':
			ip2net = optarg;
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
		case 't':
			rc = parse_long(optarg, &pto);
			if (rc != 0) {
				/* ignore option */
				pto = -1;
				continue;
			}
			break;
		case 'T':
			traffic_class = optarg;
			if (strlen(traffic_class) == 0 ||
			    strlen(traffic_class) >= LNET_MAX_STR_LEN) {
				cYAML_build_error(-1, -1, "ni", "add",
						  "Invalid traffic-class argument",
						  &err_rc);
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				goto failed;
			}
			break;
		case 'S':
			rc = parse_long(optarg, &tos);
			if (rc || tos < -1 || tos > 0xff) {
				cYAML_build_error(-1, -1, "ni", "add",
						  "Invalid ToS argument",
						  &err_rc);
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				goto failed;
			}
			break;
		case '?':
			print_help(net_cmds, "net", "add");
		default:
			return 0;
		}
	}

	if (nid_request) {
		if (net_id) {
			fprintf(stdout, "--net is invalid with --nid option\n");
			return -EINVAL;
		}
		net_id = libcfs_net2str(nw_descr.nw_id);
	}
#ifdef HAVE_KFILND
	if (auth_key > 0 && LNET_NETTYP(nw_descr.nw_id) == KFILND) {
		tunables.lt_tun.lnd_tun_u.lnd_kfi.lnd_auth_key = auth_key;
		found = true;
	}

	if (traffic_class && LNET_NETTYP(nw_descr.nw_id) == KFILND &&
	    strlen(traffic_class) < LNET_MAX_STR_LEN) {
		strcpy(&tunables.lt_tun.lnd_tun_u.lnd_kfi.lnd_traffic_class_str[0],
		       traffic_class);
		found = true;
	}
#endif

	if (LNET_NETTYP(nw_descr.nw_id) == SOCKLND) {
		tunables.lt_tun.lnd_tun_u.lnd_sock.lnd_tos = tos;
		found = true;
	} else if (LNET_NETTYP(nw_descr.nw_id) == O2IBLND) {
		tunables.lt_tun.lnd_tun_u.lnd_o2ib.lnd_tos = tos;
		found = true;
	}

	if (LNET_NETTYP(nw_descr.nw_id) == SOCKLND && (cpp > -1)) {
		tunables.lt_tun.lnd_tun_u.lnd_sock.lnd_conns_per_peer = cpp;
		found = true;
	} else if (LNET_NETTYP(nw_descr.nw_id) == O2IBLND && (cpp > -1)) {
		tunables.lt_tun.lnd_tun_u.lnd_o2ib.lnd_conns_per_peer = cpp;
		found = true;
	}

	tunables.lt_cmn.lct_peer_timeout = pto;
	tunables.lt_cmn.lct_peer_tx_credits = pc;
	tunables.lt_cmn.lct_peer_rtr_credits = pbc;
	tunables.lt_cmn.lct_max_tx_credits = cre;
	if (pto >= 0 || pc > 0 || pbc > 0 || cre > 0)
		found = true;

	if (found && LNET_NETTYP(nw_descr.nw_id) == O2IBLND)
		tunables.lt_tun.lnd_tun_u.lnd_o2ib.lnd_map_on_demand = UINT_MAX;

	rc = yaml_lnet_config_ni(net_id, ip2net, &nw_descr,
				 found ? &tunables : NULL, -1,
				 (cpt_rc == 0) ? global_cpts : NULL,
				 LNET_GENL_VERSION, NLM_F_CREATE, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		if (global_cpts != NULL)
			cfs_expr_list_free(global_cpts);
		if (rc == 0 && !skip_mr_route_setup)
			rc = lustre_lnet_setup_mrrouting(&err_rc);
		return rc;
	}
old_api:
	rc = lustre_lnet_config_ni(&nw_descr,
				   (cpt_rc == 0) ? global_cpts: NULL,
				   ip2net, (found) ? &tunables : NULL,
				   cpp, &err_rc);

	if (global_cpts != NULL)
		cfs_expr_list_free(global_cpts);

failed:
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	if (rc == LUSTRE_CFG_RC_NO_ERR && !skip_mr_route_setup) {
		err_rc = NULL;
		rc = lustre_lnet_setup_mrrouting(&err_rc);

		if (rc != LUSTRE_CFG_RC_NO_ERR)
			cYAML_print_tree2file(stderr, err_rc);

		cYAML_free_tree(err_rc);
	}

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
		{ .name = NULL }
	};

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

	rc = yaml_lnet_route(network, gateway, -1, -1, -1, LNET_GENL_VERSION,
			     0, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
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
	const char *const short_options = "n:i:";
	static const struct option long_options[] = {
	{ .name = "net",	.has_arg = required_argument,	.val = 'n' },
	{ .name = "if",		.has_arg = required_argument,	.val = 'i' },
	{ .name = "nid",	.has_arg = required_argument,	.val = 'N' },
	{ .name = NULL } };
	bool nid_request = false;
	char *net_id = NULL;

	rc = check_cmd(net_cmds, "net", "del", 0, argc, argv);
	if (rc)
		return rc;

	lustre_lnet_init_nw_descr(&nw_descr);

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nw_descr.nw_id = libcfs_str2net(optarg);
			net_id = optarg;
			break;
		case 'N':
			rc = lustre_lnet_parse_interfaces(optarg, &nw_descr);
			if (rc != 0) {
				cYAML_build_error(-1, -1, "ni", "del",
						  "bad NID list",
						  &err_rc);
				goto out;
			}
			nid_request = true;
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

	if (nid_request) {
		if (net_id) {
			fprintf(stdout, "--net is invalid with --nid option\n");
			return -EINVAL;
		}
		net_id = libcfs_net2str(nw_descr.nw_id);
	}

	rc = yaml_lnet_config_ni(net_id, NULL, &nw_descr, NULL, -1, NULL,
				 LNET_GENL_VERSION, 0, stdout);
	if (rc <= 0) {
		if (rc != -EOPNOTSUPP)
			return rc;
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
	const char *const short_options = "c:n:g:p:v";
	static const struct option long_options[] = {
		{ .name = "net",       .has_arg = required_argument, .val = 'n' },
		{ .name = "gateway",   .has_arg = required_argument, .val = 'g' },
		{ .name = "hop-count", .has_arg = required_argument, .val = 'c' },
		{ .name = "hop",       .has_arg = required_argument, .val = 'c' },
		{ .name = "priority",  .has_arg = required_argument, .val = 'p' },
		{ .name = "verbose",   .has_arg = no_argument,	     .val = 'v' },
		{ .name = NULL }
	};

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

	rc = yaml_lnet_route(network, gateway, hop, prio, -1,
			     detail, NLM_F_DUMP, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
	rc = lustre_lnet_show_route(network, gateway, hop, prio,
				    detail ? 1 : 0, -1,
				    &show_rc, &err_rc, false);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int set_value_helper(int argc, char **argv, int cmd,
			    int (*cb)(int, bool, char*, int, int, struct cYAML**))
{
	char *nidstr = NULL;
	long int healthv = -1;
	bool all = false;
	long int state = -1;
	long int cpp = -1;
	int rc, opt;
	struct cYAML *err_rc = NULL;
	const char *const short_options = "t:n:m:s:a";
	static const struct option long_options[] = {
		{ .name = "nid", .has_arg = required_argument, .val = 'n' },
		{ .name = "health", .has_arg = required_argument, .val = 't' },
		{ .name = "conns-per-peer", .has_arg = required_argument, .val = 'm' },
		{ .name = "state", .has_arg = required_argument, .val = 's' },
		{ .name = "all", .has_arg = no_argument, .val = 'a' },
		{ .name = NULL }
	};

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nidstr = optarg;
			break;
		case 't':
			if (parse_long(optarg, &healthv) != 0)
				healthv = -1;
			break;
		case 's':
			if (cmd != LNET_CMD_PEERS ||
			    parse_long(optarg, &state) != 0)
				state = -1;
			break;
		case 'm':
			if (cmd != LNET_CMD_NETS ||
			    parse_long(optarg, &cpp) != 0)
				cpp = -1;
			break;

		case 'a':
			all = true;
			break;
		default:
			return 0;
		}
	}

	rc = cb(healthv, all, nidstr, cmd == LNET_CMD_PEERS ? state : cpp, -1,
		&err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

int yaml_lnet_config_ni_healthv(int healthv, bool all, char *nidstr, int cpp,
				int seq_no, struct cYAML **err_rc)
{
	struct lnet_ioctl_config_lnd_tunables tunables;
	struct lnet_dlc_network_descr nw_descr;
	char *net_id = "<255:65535>"; /* LNET_NET_ANY */
	int rc = 0;

	/* For NI you can't have both setting all NIDs and a requested NID */
	if (!all && !nidstr)
		return -EINVAL;

	if (cpp == -1 && healthv == -1)
		return 0;

	if (nidstr) {
		net_id = strchr(nidstr, '@');
		if (!net_id)
			return -EINVAL;
		net_id++;
	}

	lustre_lnet_init_nw_descr(&nw_descr);
	nw_descr.nw_id = libcfs_str2net(net_id);

	rc = lustre_lnet_parse_interfaces(nidstr ? nidstr : "<?>", &nw_descr);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		return -EINVAL;

	memset(&tunables, 0, sizeof(tunables));
	tunables.lt_cmn.lct_peer_timeout = -1;
	if (nw_descr.nw_id == LNET_NET_ANY && cpp > -1)
		tunables.lt_tun.lnd_tun_u.lnd_sock.lnd_conns_per_peer = cpp;
	else if (LNET_NETTYP(nw_descr.nw_id) == SOCKLND && (cpp > -1))
		tunables.lt_tun.lnd_tun_u.lnd_sock.lnd_conns_per_peer = cpp;
	else if (LNET_NETTYP(nw_descr.nw_id) == O2IBLND && (cpp > -1))
		tunables.lt_tun.lnd_tun_u.lnd_o2ib.lnd_conns_per_peer = cpp;

	rc = yaml_lnet_config_ni(net_id, NULL, &nw_descr,
				 cpp != -1 ? &tunables : NULL, healthv, NULL,
				 LNET_GENL_VERSION, NLM_F_REPLACE, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
	if (cpp > -1)
		rc = lustre_lnet_config_ni_conns_per_peer(cpp, all, nidstr,
							  -1, err_rc);
	if (healthv > -1)
		rc = lustre_lnet_config_ni_healthv(healthv, all, nidstr,
						   -1, err_rc);
	return rc;
}

static int jt_set_ni_value(int argc, char **argv)
{
	int rc = check_cmd(net_cmds, "net", "set", 0, argc, argv);

	if (rc < 0)
		return rc;

	return set_value_helper(argc, argv, LNET_CMD_NETS,
				yaml_lnet_config_ni_healthv);
}

static int yaml_lnet_peer_display(yaml_parser_t *reply, bool list_only)
{
	yaml_emitter_t debug;
	int rc;

	rc = yaml_emitter_initialize(&debug);
	if (rc == 0)
		goto out_err;

	yaml_emitter_set_indent(&debug, 6);
	yaml_emitter_set_output_file(&debug, stdout);

	if (list_only) {
		bool done = false;

		while (!done) {
			yaml_event_t event;
			char *value;

			rc = yaml_parser_parse(reply, &event);
			if (rc == 0)
				goto report_reply_error;

			if (event.type != YAML_SCALAR_EVENT)
				goto merge_event;

			value = (char *)event.data.scalar.value;
			if (strcmp(value, "peer") == 0) {
				yaml_event_delete(&event);

				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)"peer list",
							     strlen("peer list"),
							     1, 0,
							     YAML_PLAIN_SCALAR_STYLE);
			} else if (strcmp(value, "primary nid") == 0) {
				yaml_event_delete(&event);

				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)"nid",
							     strlen("nid"),
							     1, 0,
							     YAML_PLAIN_SCALAR_STYLE);
				rc = yaml_emitter_emit(&debug, &event);
				if (rc == 0)
					break;

				/* Now print NID address */
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					goto report_reply_error;

				rc = yaml_emitter_emit(&debug, &event);
				if (rc == 0)
					break;

				/* skip ALL peer_ni info */
				while (event.type != YAML_SEQUENCE_END_EVENT) {
					rc = yaml_parser_parse(reply, &event);
					if (rc == 0)
						goto report_reply_error;
				}

				/* But keep sequence end event */
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					goto report_reply_error;

				if (event.type == YAML_SEQUENCE_END_EVENT) {
					yaml_event_delete(&event);

					rc = yaml_parser_parse(reply, &event);
					if (rc == 0)
						goto report_reply_error;
				}
			}
merge_event:
			rc = yaml_emitter_emit(&debug, &event);
			if (rc == 0)
				break;

			done = (event.type == YAML_DOCUMENT_END_EVENT);
		}
	} else {
		yaml_document_t errmsg;

		rc = yaml_parser_load(reply, &errmsg);
		if (rc == 1)
			rc = yaml_emitter_dump(&debug, &errmsg);
		yaml_document_delete(&errmsg);
	}
out_err:
	if (rc == 0) {
		yaml_emitter_log_error(&debug, stderr);
		rc = -EINVAL; /* Avoid reporting as reply error */
	}
report_reply_error:
	yaml_emitter_delete(&debug);

	return rc;
}

static int yaml_lnet_peer(char *prim_nid, char *nidstr, bool disable_mr,
			  int health_value, int state, bool list_only,
			  int version, int flags, FILE *fp)
{
	struct nl_sock *sk = NULL;
	const char *msg = NULL;
	yaml_emitter_t output;
	yaml_parser_t reply;
	yaml_event_t event;
	int rc;

	/* Create Netlink emitter to send request to kernel */
	sk = nl_socket_alloc();
	if (!sk)
		return -EOPNOTSUPP;

	/* Setup parser to receive Netlink packets */
	rc = yaml_parser_initialize(&reply);
	if (rc == 0) {
		nl_socket_free(sk);
		return -EOPNOTSUPP;
	}

	rc = yaml_parser_set_input_netlink(&reply, sk, false);
	if (rc == 0) {
		msg = yaml_parser_get_reader_error(&reply);
		goto free_reply;
	}

	/* Create Netlink emitter to send request to kernel */
	rc = yaml_emitter_initialize(&output);
	if (rc == 0) {
		msg = "failed to initialize emitter";
		goto free_reply;
	}

	rc = yaml_emitter_set_output_netlink(&output, sk, LNET_GENL_NAME,
					     version, LNET_CMD_PEERS, flags);
	if (rc == 0)
		goto emitter_error;

	yaml_emitter_open(&output);
	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"peer",
				     strlen("peer"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	if (prim_nid) {
		yaml_sequence_start_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_SEQ_TAG,
						     1,
						     YAML_BLOCK_SEQUENCE_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_mapping_start_event_initialize(&event, NULL,
						    (yaml_char_t *)YAML_MAP_TAG,
						    1,
						    YAML_BLOCK_MAPPING_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"primary nid",
					     strlen("primary nid"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)prim_nid,
					     strlen(prim_nid), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		if (disable_mr) {
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"Multi-Rail",
						     strlen("Multi-Rail"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_BOOL_TAG,
						     (yaml_char_t *)"False",
						     strlen("False"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		}

		if (state != -1) {
			char peer_state[INT_STRING_LEN];

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"peer state",
						     strlen("peer state"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			snprintf(peer_state, sizeof(peer_state), "%d", state);
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)peer_state,
						     strlen(peer_state), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		}

		if (!nidstr && health_value == -1)
			goto skip_peer_nis;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"peer ni",
					     strlen("peer ni"), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_sequence_start_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_SEQ_TAG,
						     1, YAML_BLOCK_SEQUENCE_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		if (nidstr) {
			struct nid_node head, *entry;
			int count = 0;

			/* If we have LNET_ANY_NID and its NLM_F_REPLACE we
			 * treat it as the all flag case for lnetctl peer set
			 */
			if (strcmp(nidstr, "<?>") == 0) {
				yaml_mapping_start_event_initialize(&event, NULL,
								    (yaml_char_t *)YAML_MAP_TAG,
								    1, YAML_BLOCK_MAPPING_STYLE);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;

				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)"nid",
							     strlen("nid"), 1, 0,
							     YAML_PLAIN_SCALAR_STYLE);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;

				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)nidstr,
							     strlen(nidstr), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;

				yaml_mapping_end_event_initialize(&event);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;

				goto handle_health;
			}

			NL_INIT_LIST_HEAD(&head.children);
			nl_init_list_head(&head.list);
			rc = lustre_lnet_parse_nid_range(&head, nidstr, &msg);
			if (rc < 0) {
				fprintf(stdout, "can't parse nidrange: \"%s\"\n", nidstr);
				lustre_lnet_free_list(&head);
				yaml_emitter_delete(&output);
				errno = rc;
				rc = 0;
				goto free_reply;
			}

			if (nl_list_empty(&head.children)) {
				lustre_lnet_free_list(&head);
				yaml_emitter_delete(&output);
				msg = "Unable to parse nidlist: did not expand to any nids";
				errno = -ENOENT;
				rc = 0;
				goto free_reply;
			}
			rc = 1; /* one means its working */

			nl_list_for_each_entry(entry, &head.children, list) {
				char *nid = entry->nidstr;

				if (count++ > LNET_MAX_NIDS_PER_PEER) {
					lustre_lnet_free_list(&head);
					yaml_emitter_delete(&output);
					msg = "Unable to parse nidlist: specifies more NIDs than allowed";
					errno = -E2BIG;
					rc = 0;
					goto free_reply;
				}

				yaml_mapping_start_event_initialize(&event, NULL,
								    (yaml_char_t *)YAML_MAP_TAG,
								    1, YAML_BLOCK_MAPPING_STYLE);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;

				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)"nid",
							     strlen("nid"), 1, 0,
							     YAML_PLAIN_SCALAR_STYLE);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;

				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)nid,
							     strlen(nid), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;

				yaml_mapping_end_event_initialize(&event);
				rc = yaml_emitter_emit(&output, &event);
				if (rc == 0)
					goto emitter_error;
			}
			lustre_lnet_free_list(&head);
		}
handle_health:
		if (health_value >= 0) {
			char health[INT_STRING_LEN];

			/* Create the mapping for 'health stats'. The value field for
			 * the mapping is not provided so its treated as a empty string.
			 */
			yaml_mapping_start_event_initialize(&event, NULL,
							    (yaml_char_t *)YAML_MAP_TAG,
							    1, YAML_BLOCK_MAPPING_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"health stats",
						     strlen("health stats"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			/* Setup all mappings for data related to the 'health stats' */
			yaml_mapping_start_event_initialize(&event, NULL,
							    (yaml_char_t *)YAML_MAP_TAG,
							    1, YAML_BLOCK_MAPPING_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"health value",
						     strlen("health value"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			snprintf(health, sizeof(health), "%d", health_value);
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)health,
						     strlen(health), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_mapping_end_event_initialize(&event);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_mapping_end_event_initialize(&event);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		}

		yaml_sequence_end_event_initialize(&event);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
skip_peer_nis:
		yaml_mapping_end_event_initialize(&event);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;

		yaml_sequence_end_event_initialize(&event);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
	} else {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"",
					     strlen(""), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
	}

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_document_end_event_initialize(&event, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	rc = yaml_emitter_close(&output);
emitter_error:
	if (rc == 0) {
		yaml_emitter_log_error(&output, stderr);
		rc = -EINVAL;
	} else {
		rc = yaml_lnet_peer_display(&reply, list_only);
		if (rc == 0) {
			msg = yaml_parser_get_reader_error(&reply);
			/* If we didn't find any peers just be silent */
			if (msg && strcmp(msg, "No peers found") == 0)
				rc = 1;
		}
	}
	yaml_emitter_delete(&output);
free_reply:
	if (rc == 0) {
		yaml_lnet_print_error(flags, "peer", msg);
		rc = -EINVAL;
	}
	yaml_parser_delete(&reply);
	nl_socket_free(sk);

	return rc == 1 ? 0 : rc;
}

int yaml_lnet_config_peer_ni_healthv(int healthv, bool all, char *lpni_nid,
				     int state, int seq_no, struct cYAML **err_rc)
{
	int rc;

	rc = yaml_lnet_peer(lpni_nid ? lpni_nid : "<?>", all ? "<?>" : NULL,
			    false, healthv, state, false, LNET_GENL_VERSION,
			    NLM_F_REPLACE, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
	if (state == -1)
		rc = lustre_lnet_config_peer_ni_healthv(healthv, all, lpni_nid,
							seq_no, err_rc);
	else
		rc = lustre_lnet_set_peer_state(state, lpni_nid, -1, err_rc);

	return rc;
}

static int jt_set_peer_ni_value(int argc, char **argv)
{
	int rc = check_cmd(peer_cmds, "peer", "set", 0, argc, argv);

	if (rc < 0)
		return rc;

	return set_value_helper(argc, argv, LNET_CMD_PEERS,
				yaml_lnet_config_peer_ni_healthv);
}

static int yaml_debug_recovery(enum lnet_health_type type)
{
	yaml_parser_t setup, reply;
	yaml_document_t results;
	yaml_emitter_t output;
	const char *msg = NULL;
	struct nl_sock *sk;
	char *config;
	int rc = 0;

	switch (type) {
	case LNET_HEALTH_TYPE_LOCAL_NI:
		config = "dbg-recov:\n  queue_type: 0\n";
		break;
	case  LNET_HEALTH_TYPE_PEER_NI:
		config = "dbg-recov:\n  queue_type: 1\n";
		break;
	default:
		rc = -EINVAL;
		break;
	}
	if (rc < 0)
		return rc;

	/* Initialize configuration parser */
	rc = yaml_parser_initialize(&setup);
	if (rc == 0) {
		yaml_parser_log_error(&setup, stderr, NULL);
		yaml_parser_delete(&setup);
		return -EOPNOTSUPP;
	}

	yaml_parser_set_input_string(&setup, (unsigned char *)config,
				     strlen(config));
	rc = yaml_parser_load(&setup, &results);
	if (rc == 0) {
		yaml_parser_log_error(&setup, stderr, NULL);
		yaml_parser_delete(&setup);
		return -EOPNOTSUPP;
	}
	yaml_parser_delete(&setup);

	/* Create Netlink emitter to send request to kernel */
	sk = nl_socket_alloc();
	if (!sk) {
		yaml_document_delete(&results);
		return -EOPNOTSUPP;
	}

	/* Setup parser to recieve Netlink packets */
	rc = yaml_parser_initialize(&reply);
	if (rc == 0) {
		yaml_document_delete(&results);
		nl_socket_free(sk);
		return -EOPNOTSUPP;
	}

	rc = yaml_parser_set_input_netlink(&reply, sk, false);
	if (rc == 0)
		goto free_reply;

	yaml_emitter_initialize(&output);
	rc = yaml_emitter_set_output_netlink(&output, sk, LNET_GENL_NAME,
					     LNET_GENL_VERSION,
					     LNET_CMD_DBG_RECOV, NLM_F_DUMP);
	if (rc == 1) /* 1 is success */
		rc = yaml_emitter_dump(&output, &results);
	if (rc == 0) {
		yaml_emitter_log_error(&output, stderr);
		rc = -EINVAL;
	} else {
		yaml_document_t errmsg;

		rc = yaml_parser_load(&reply, &errmsg);
		if (rc == 1) {
			yaml_emitter_t debug;

			rc = yaml_emitter_initialize(&debug);
			if (rc == 1) {
				yaml_emitter_set_indent(&debug,
							LNET_DEFAULT_INDENT);
				yaml_emitter_set_output_file(&debug,
							     stdout);
				rc = yaml_emitter_dump(&debug, &errmsg);
			}
			yaml_emitter_delete(&debug);
		} else {
			msg = yaml_parser_get_reader_error(&reply);
			if (errno == -ENOENT)
				rc = 1;
		}
		yaml_document_delete(&errmsg);
	}
	yaml_emitter_delete(&output);
free_reply:
	if (rc == 0) {
		if (!msg)
			msg = yaml_parser_get_reader_error(&reply);

		fprintf(stdout, "Operation failed: %s\n", msg);
	}
	yaml_parser_delete(&reply);
	nl_socket_free(sk);

	return rc == 1 ? 0 : rc;
}

static int jt_show_recovery(int argc, char **argv)
{
	int rc, opt;
	struct cYAML *err_rc = NULL, *show_rc = NULL;
	const char *const short_options = "lp";
	static const struct option long_options[] = {
		{ .name = "local", .has_arg = no_argument, .val = 'l' },
		{ .name = "peer", .has_arg = no_argument, .val = 'p' },
		{ .name = NULL }
	};
	enum lnet_health_type type = -1;

	rc = check_cmd(debug_cmds, "debug", "recovery", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'l':
			type = LNET_HEALTH_TYPE_LOCAL_NI;
			break;
		case 'p':
			type = LNET_HEALTH_TYPE_PEER_NI;
			break;
		default:
			return 0;
		}
	}

	rc = yaml_debug_recovery(type);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
	switch (type) {
	case LNET_HEALTH_TYPE_LOCAL_NI:
		rc = lustre_lnet_show_local_ni_recovq(-1, &show_rc, &err_rc);
		break;
	case LNET_HEALTH_TYPE_PEER_NI:
		rc = lustre_lnet_show_peer_ni_recovq(-1, &show_rc, &err_rc);
		break;
	default:
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		break;
	}

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (show_rc)
		cYAML_print_tree(show_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(show_rc);

	return rc;
}

static int jt_show_peer_debug_info(int argc, char **argv)
{
	int rc, opt;
	struct cYAML *err_rc = NULL;
	char *peer_nid = optarg;
	const char *const short_opts = "k";
	const struct option long_opts[] = {
	{ .name = "nid", .has_arg = required_argument, .val = 'k' },
	{ .name = NULL } };

	rc = check_cmd(debug_cmds, "debug", "peer", 0, argc, argv);

	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_opts,
				   long_opts, NULL)) != -1) {
		switch (opt) {
		case 'k':
			peer_nid = optarg;
			break;
		default:
			return 0;
		}
	}

	rc = lustre_lnet_show_peer_debug_info(peer_nid, -1, &err_rc);

	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

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

	rc = yaml_lnet_config_ni(network, NULL, NULL, NULL, -1, NULL,
				 detail, NLM_F_DUMP, stdout);
	if (rc <= 0) {
		if (rc != -EOPNOTSUPP)
			return rc;
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
	long int idx = -1;
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
			rc = parse_long(optarg, &idx);
			if (rc != 0 || idx < -1) {
				printf("Invalid index \"%s\"\n", optarg);
				return -EINVAL;
			}
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

	rc = lustre_lnet_show_max_recovery_ping_interval(-1, &show_rc, &err_rc);
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

	return cfs_parser(argc, argv, lnet_cmds);
}

static int jt_route(int argc, char **argv)
{
	int rc;

	rc = check_cmd(route_cmds, "route", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, route_cmds);
}

static int jt_net(int argc, char **argv)
{
	int rc;

	rc = check_cmd(net_cmds, "net", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, net_cmds);
}

static int jt_routing(int argc, char **argv)
{
	int rc;

	rc = check_cmd(routing_cmds, "routing", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, routing_cmds);
}

static int jt_stats(int argc, char **argv)
{
	int rc;

	rc = check_cmd(stats_cmds, "stats", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, stats_cmds);
}

static int jt_debug(int argc, char **argv)
{
	int rc;

	rc = check_cmd(debug_cmds, "debug", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, debug_cmds);
}

static int jt_global(int argc, char **argv)
{
	int rc;

	rc = check_cmd(global_cmds, "global", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, global_cmds);
}

static int jt_peers(int argc, char **argv)
{
	int rc;

	rc = check_cmd(peer_cmds, "peer", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, peer_cmds);
}

static int jt_set(int argc, char **argv)
{
	int rc;

	rc = check_cmd(set_cmds, "set", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, set_cmds);
}

static int jt_udsp(int argc, char **argv)
{
	int rc;

	rc = check_cmd(udsp_cmds, "udsp", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, udsp_cmds);
}

static int jt_fault(int argc, char **argv)
{
	int rc;

	rc = check_cmd(fault_cmds, "fault", NULL, 2, argc, argv);
	if (rc)
		return rc;

	return cfs_parser(argc, argv, fault_cmds);
}

static int yaml_import_global_settings(char *key, unsigned long value,
				       char cmd, struct cYAML *show_rc,
				       struct cYAML *err_rc)
{
	int rc = 0;

	if (strcmp("numa_range", key) == 0) {
		if (cmd == 'a' || cmd == 'd') {
			if (cmd == 'd')
				value = 0;
			rc = lustre_lnet_config_numa_range(value, -1,
							   &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_numa_range(-1, &show_rc,
							 &err_rc);
		}
	} else if (strcmp("max_interfaces", key) == 0 ||
		   strcmp("max_intf", key) == 0) {
		if (cmd == 'a' || cmd == 'd') {
			if (cmd == 'd')
				value = LNET_INTERFACES_MAX_DEFAULT;
			rc = lustre_lnet_config_max_intf(value, -1,
							 &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_max_intf(-1, &show_rc,
						       &err_rc);
		}
	} else if (strcmp("discovery", key) == 0) {
		if (cmd == 'a' || cmd == 'd') {
			if (cmd == 'd')
				value = 1;
			rc = lustre_lnet_config_discovery(value, -1,
							  &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_discovery(-1, &show_rc,
							&err_rc);
		}
	} else if (strcmp("drop_asym_route", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_drop_asym_route(value,
								-1,
								&err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_drop_asym_route(-1, &show_rc,
							      &err_rc);
		}
	} else if (strcmp("retry_count", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_retry_count(value, -1,
							    &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_retry_count(-1, &show_rc,
							  &err_rc);
		}
	} else if (strcmp("transaction_timeout", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_transaction_to(value, -1,
							       &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_transaction_to(-1, &show_rc,
							     &err_rc);
		}
	} else if (strcmp("health_sensitivity", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_hsensitivity(value, -1,
							     &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_hsensitivity(-1, &show_rc,
							   &err_rc);
		}
	} else if (strcmp("recovery_interval", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_recov_intrv(value, -1,
							    &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_recov_intrv(-1, &show_rc,
							  &err_rc);
		}
	} else if (strcmp("router_sensitivity", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_rtr_sensitivity(value, -1,
								&err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_rtr_sensitivity(-1, &show_rc,
							      &err_rc);
		}
	} else if (strcmp("lnd_timeout", key) == 0) {
		if (cmd == 'a') {
		} else if (cmd == 's') {
			rc = lustre_lnet_show_lnd_timeout(-1, &show_rc,
							  &err_rc);
		}
	} else if (strcmp("response_tracking", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_response_tracking(value, -1,
								  &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_response_tracking(-1, &show_rc,
								&err_rc);
		}
	} else if (strcmp("recovery_limit", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_recovery_limit(value, -1,
							       &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_recovery_limit(-1, &show_rc,
							     &err_rc);
		}
	} else if (strcmp("max_recovery_ping_interval", key) == 0) {
		if (cmd == 'a') {
			rc = lustre_lnet_config_max_recovery_ping_interval(value, -1,
									   &err_rc);
		} else if (cmd == 's') {
			rc = lustre_lnet_show_max_recovery_ping_interval(-1, &show_rc,
									 &err_rc);
		}
	}

	return rc;
}

static char *global_params[] = {
	"numa_range",
	"max_interfaces",
	"max_intf",
	"discovery",
	"drop_asym_route",
	"retry_count",
	"transaction_timeout",
	"health_sensitivity",
	"recovery_interval",
	"router_sensitivity",
	"lnd_timeout",
	"response_tracking",
	"recovery_limit",
	"max_recovery_ping_interval"
};

static bool key_is_global_param(const char *key)
{
	int i;

	for (i = 0; i < sizeof(global_params)/sizeof(global_params[0]); i++) {
		if (!strcmp(key, global_params[i]))
			return true;
	}
	return false;
}

static int jt_import(int argc, char **argv)
{
	char *file = NULL;
	struct cYAML *err_rc = NULL;
	struct cYAML *show_rc = NULL;
	int rc = 0, return_rc = 0, opt, opt_found = 0;
	char *yaml_blk = NULL, *buf, cmd = 'a';
	int flags = NLM_F_CREATE;
	bool release = true;
	char err_str[256];
	struct stat st;
	FILE *input;
	size_t len;
	const char *const short_options = "adseh";
	static const struct option long_options[] = {
		{ .name = "add",  .has_arg = no_argument, .val = 'a' },
		{ .name = "del",  .has_arg = no_argument, .val = 'd' },
		{ .name = "show", .has_arg = no_argument, .val = 's' },
		{ .name = "exec", .has_arg = no_argument, .val = 'e' },
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL }
	};
	bool done = false, unspec = true;
	yaml_parser_t setup, reply;
	struct nl_sock *sk = NULL;
	int op = LNET_CMD_UNSPEC;
	const char *msg = NULL;
	yaml_emitter_t output;
	yaml_event_t event;

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		opt_found = 1;
		switch (opt) {
		case 'a':
			/* default is NLM_F_CREATE */
			cmd = opt;
			break;
		case 'd':
			flags = 0; /* Netlink delete cmd */
			cmd = opt;
			break;
		case 's':
			flags = NLM_F_DUMP;
			cmd = opt;
			break;
		case 'e':
			/* use NLM_F_CREATE for discover */
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

	/* file always takes precedence */
	if (file != NULL) {
		/* Set a file input. */
		input = fopen(file, "rb");
		if (!input) {
			rc = -errno;
			snprintf(err_str, sizeof(err_str),
				 "cannot open '%s': %s", file,
				 strerror(errno));
			cYAML_build_error(-1, -1, "yaml", "builder",
					  err_str,
					  &err_rc);
			goto err;
		}
	} else {
		input = stdin;
	}

	/* Create Netlink emitter to send request to kernel */
	sk = nl_socket_alloc();
	if (!sk)
		goto old_api;

	/* Setup parser to receive Netlink packets */
	rc = yaml_parser_initialize(&reply);
	if (rc == 0) {
		nl_socket_free(sk);
		goto old_api;
	}

	rc = yaml_parser_set_input_netlink(&reply, sk, false);
	if (rc == 0) {
		msg = yaml_parser_get_reader_error(&reply);
		goto free_reply;
	}

	/* Initialize configuration parser */
	rc = yaml_parser_initialize(&setup);
	if (rc == 0) {
		yaml_parser_log_error(&setup, stderr, "import: ");
		yaml_parser_delete(&setup);
		return -EINVAL;
	}

	yaml_parser_set_input_file(&setup, input);

	while (!done) {
		if (!yaml_parser_parse(&setup, &event)) {
			yaml_parser_log_error(&setup, stderr, "import: ");
			break;
		}

		if (event.type != YAML_SCALAR_EVENT)
			goto skip_test;

		if (!strcmp((char *)event.data.scalar.value, "net") &&
		    op != LNET_CMD_ROUTES && cmd != 'e') {
			if (op != LNET_CMD_UNSPEC) {
				rc = yaml_netlink_complete_emitter(&output);
				if (rc == 0)
					goto emitter_error;
			}
			op = LNET_CMD_NETS;

			rc = yaml_netlink_setup_emitter(&output, sk,
							LNET_GENL_NAME,
							LNET_GENL_VERSION,
							flags, op, true);
			if (rc == 0)
				goto emitter_error;

			unspec = false;
		} else if (!strcmp((char *)event.data.scalar.value, "peer") &&
			   cmd != 'e') {
			if (op != LNET_CMD_UNSPEC) {
				rc = yaml_netlink_complete_emitter(&output);
				if (rc == 0)
					goto emitter_error;
			}
			op = LNET_CMD_PEERS;

			rc = yaml_netlink_setup_emitter(&output, sk,
							LNET_GENL_NAME,
							LNET_GENL_VERSION,
							flags, op, true);
			if (rc == 0)
				goto emitter_error;

			unspec = false;
		} else if (!strcmp((char *)event.data.scalar.value, "route") &&
			   cmd != 'e') {
			if (op != LNET_CMD_UNSPEC) {
				rc = yaml_netlink_complete_emitter(&output);
				if (rc == 0)
					goto emitter_error;
			}
			op = LNET_CMD_ROUTES;

			rc = yaml_netlink_setup_emitter(&output, sk,
							LNET_GENL_NAME,
							LNET_GENL_VERSION,
							flags, op, true);
			if (rc == 0)
				goto emitter_error;

			unspec = false;
		} else if ((!strcmp((char *)event.data.scalar.value, "discover") ||
			    !strcmp((char *)event.data.scalar.value, "ping")) &&
			   cmd == 'e') {
			if (op != LNET_CMD_UNSPEC) {
				rc = yaml_netlink_complete_emitter(&output);
				if (rc == 0)
					goto emitter_error;
			}
			op = LNET_CMD_PING;

			if (!strcmp((char *)event.data.scalar.value, "ping"))
				flags = NLM_F_DUMP;

			rc = yaml_netlink_setup_emitter(&output, sk,
							LNET_GENL_NAME,
							LNET_GENL_VERSION,
							flags, op, true);
			if (rc == 0)
				goto emitter_error;

			unspec = false;
		} else if (!strcmp((char *)event.data.scalar.value, "global")) {
			if (op != LNET_CMD_UNSPEC) {
				rc = yaml_netlink_complete_emitter(&output);
				if (rc == 0)
					goto emitter_error;
			}
			op = LNET_CMD_UNSPEC;
		} else if (op == LNET_CMD_UNSPEC) {
			struct cYAML *err_rc = NULL;
			long int value;
			char *key;
			char errmsg[LNET_MAX_STR_LEN];

			key = strdup((char *)event.data.scalar.value);
			if (!key_is_global_param(key)) {
				snprintf(errmsg, LNET_MAX_STR_LEN,
					 "invalid key '%s'", key);
				errno = rc = -EINVAL;
				yaml_lnet_print_error(flags, "import", errmsg);
				goto free_reply;
			}

			rc = yaml_parser_parse(&setup, &event);
			if (rc == 0) {
				yaml_parser_log_error(&setup, stderr,
						      "import: ");
				goto emitter_error;
			}

			if (!strlen((char *)event.data.scalar.value)) {
				snprintf(errmsg, LNET_MAX_STR_LEN,
					 "no value specified for key '%s'",
					 key);
				errno = rc = -EINVAL;
				yaml_lnet_print_error(flags, "import", errmsg);
				goto free_reply;
			}

			rc = parse_long((char *)event.data.scalar.value,
					&value);
			if (rc != 0) {
				snprintf(errmsg, LNET_MAX_STR_LEN,
					 "invalid value '%s' for key '%s'",
					 (char *)event.data.scalar.value, key);
				errno = rc = -EINVAL;
				yaml_lnet_print_error(flags, "import", errmsg);
				goto free_reply;
			}

			rc = yaml_import_global_settings(key, value, cmd,
							 show_rc, err_rc);
			if (rc != LUSTRE_CFG_RC_NO_ERR)
				cYAML_print_tree2file(stderr, err_rc);
			else
				rc = 1;
		}
skip_test:
		if (op != LNET_CMD_UNSPEC) {
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				break;
		}

		done = (event.type == YAML_STREAM_END_EVENT);
	}
emitter_error:
	if (rc == 0) {
		yaml_emitter_log_error(&output, stderr);
		yaml_emitter_delete(&output);
		rc = -EINVAL;
	} else if (!unspec) {
		yaml_document_t errmsg;

		rc = yaml_parser_load(&reply, &errmsg);
		if (rc == 1 && (flags & NLM_F_DUMP)) {
			yaml_emitter_t debug;

			rc = yaml_emitter_initialize(&debug);
			if (rc == 1) {
				yaml_emitter_set_indent(&debug,
							LNET_DEFAULT_INDENT);
				yaml_emitter_set_output_file(&debug,
							     stdout);
				rc = yaml_emitter_dump(&debug, &errmsg);
			}
			yaml_emitter_delete(&debug);
		} else {
			msg = yaml_parser_get_reader_error(&reply);
		}
		yaml_emitter_delete(&output);
		yaml_document_delete(&errmsg);
	}
free_reply:
	if (rc == 0) {
		yaml_lnet_print_error(flags, "import", msg);
		rc = -EINVAL;
	}
	yaml_parser_delete(&reply);
	yaml_parser_delete(&setup);
	nl_socket_free(sk);
	if (input)
		fclose(input);

	return rc == 1 ? 0 : rc;
old_api:
	/* assume that we're getting our input from stdin */
	rc = fstat(fileno(input), &st);
	if (rc < 0) {
		snprintf(err_str, sizeof(err_str),
			 "cannot get file stats '%s': %s", file,
			 strerror(-rc));
		cYAML_build_error(-1, -1, "yaml", "builder",
				  err_str,
				  &err_rc);
		goto err;
	}

	yaml_blk = buf = malloc(st.st_size);
	if (!yaml_blk) {
		rc = -ENOMEM;
		snprintf(err_str, sizeof(err_str),
			 "failed to allocate buffer: %s",
			 strerror(-rc));
		cYAML_build_error(-1, -1, "yaml", "builder",
				  err_str,
				  &err_rc);
		goto err;
	}
	len = st.st_size;

	while (fgets(buf, len, input) != NULL) {
		char *seq = strstr(buf, "-     ");

		if (seq) {
			int skip;

			seq[0] = ' ';
			skip = strspn(seq, " ");
			if (skip) {
				seq += skip - 2;
				seq[0] = '-';
			}
			/* PyYAML format has libyaml free the
			 * buffer for us.
			 */
			release = false;
		}
		buf += strlen(buf);
		len -= strlen(buf);
	}

	switch (cmd) {
	case 'a':
		rc = lustre_yaml_config(yaml_blk, st.st_size, &err_rc);
		return_rc = lustre_yaml_exec(yaml_blk, st.st_size, &show_rc,
					     &err_rc);
		cYAML_print_tree(show_rc);
		cYAML_free_tree(show_rc);
		break;
	case 'd':
		rc = lustre_yaml_del(yaml_blk, st.st_size, &err_rc);
		break;
	case 's':
		rc = lustre_yaml_show(yaml_blk, st.st_size, &show_rc,
				      &err_rc);
		cYAML_print_tree(show_rc);
		cYAML_free_tree(show_rc);
		break;
	case 'e':
		rc = lustre_yaml_exec(yaml_blk, st.st_size, &show_rc,
				      &err_rc);
		cYAML_print_tree(show_rc);
		cYAML_free_tree(show_rc);
		break;
	}
err:
	if (yaml_blk && release)
		free(yaml_blk);
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
	int flags = NLM_F_DUMP;
	int rc;
	FILE *f = NULL;
	int opt;
	bool backup = false;
	char *file = NULL;
	const char *const short_options = "bh";
	static const struct option long_options[] = {
		{ .name = "backup", .has_arg = no_argument, .val = 'b' },
		{ .name = "help", .has_arg = no_argument, .val = 'h' },
		{ .name = NULL }
	};

	while ((opt = getopt_long(argc, argv, short_options,
				   long_options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			flags |= NLM_F_DUMP_FILTERED;
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

	rc = yaml_lnet_config_ni(NULL, NULL, NULL, NULL, -1, NULL,
				 flags & NLM_F_DUMP_FILTERED ? 1 : 2,
				 flags, f);
	if (rc < 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
	}

	rc = yaml_lnet_route(NULL, NULL, -1, -1, -1, LNET_GENL_VERSION,
			     flags, f);
	if (rc < 0) {
		if (rc == -EOPNOTSUPP)
			goto old_route;
	}

	rc = lustre_lnet_show_routing(-1, &show_rc, &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = yaml_lnet_peer(NULL, NULL, false, -1, false, false,
			    flags & NLM_F_DUMP_FILTERED ? 0 : 3,
			   flags, f);
	if (rc < 0) {
		if (rc == -EOPNOTSUPP)
			goto old_peer;
	}
	goto show_others;

old_api:
	rc = lustre_lnet_show_net(NULL, 2, -1, &show_rc, &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}
old_route:
	rc = lustre_lnet_show_route(NULL, NULL, -1, -1, 1, -1, &show_rc,
				    &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_routing(-1, &show_rc, &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}
old_peer:
	rc = lustre_lnet_show_peer(NULL, 2, -1, &show_rc, &err_rc, backup);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}
show_others:
	rc = lustre_lnet_show_numa_range(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_max_intf(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_discovery(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_drop_asym_route(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_retry_count(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_transaction_to(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_hsensitivity(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_recov_intrv(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_rtr_sensitivity(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_lnd_timeout(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_response_tracking(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_recovery_limit(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_max_recovery_ping_interval(-1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
		cYAML_free_tree(err_rc);
		err_rc = NULL;
	}

	rc = lustre_lnet_show_udsp(-1, -1, &show_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		cYAML_print_tree2file(f, err_rc);
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
	int flags = cmd == LNETCTL_ADD_CMD ? NLM_F_CREATE : 0;
	int rc = LUSTRE_CFG_RC_NO_ERR, opt;
	bool is_mr = true;
	char *prim_nid = NULL, *nidstr = NULL;
	char err_str[LNET_MAX_STR_LEN] = "Error";
	struct cYAML *err_rc = NULL;
	int force_lock = 0;
	const char *const short_opts = "k:m:n:f:l";
	const struct option long_opts[] = {
	{ .name = "prim_nid",	.has_arg = required_argument,	.val = 'k' },
	{ .name = "non_mr",	.has_arg = no_argument,		.val = 'm' },
	{ .name = "nid",	.has_arg = required_argument,	.val = 'n' },
	{ .name = "force",      .has_arg = no_argument,		.val = 'f' },
	{ .name = "lock_prim",	.has_arg = no_argument,		.val = 'l' },
	{ .name = NULL } };

	rc = check_cmd(peer_cmds, "peer",
		       cmd == LNETCTL_ADD_CMD ? "add" : "del", 2, argc, argv);
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
		case 'f':
			if (cmd == LNETCTL_ADD_CMD) {
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				snprintf(err_str, LNET_MAX_STR_LEN,
					 "Unrecognized option '-%c'", opt);
			}
			force_lock = 1;
			flags |= NLM_F_EXCL;
			break;
		case 'l':
			if (cmd == LNETCTL_DEL_CMD) {
				rc = LUSTRE_CFG_RC_BAD_PARAM;
				snprintf(err_str, LNET_MAX_STR_LEN,
					 "Unrecognized option '-%c'", opt);
			}
			force_lock = 1;
			flags |= NLM_F_EXCL;
			break;
		case '?':
			print_help(peer_cmds, "peer",
				   cmd == LNETCTL_ADD_CMD ? "add" : "del");
		default:
			return 0;
		}
	}

	rc = yaml_lnet_peer(prim_nid, nidstr, !is_mr, -1, -1, false,
			    LNET_GENL_VERSION, flags, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
	rc = lustre_lnet_modify_peer(prim_nid, nidstr, is_mr, cmd,
				     force_lock, -1, &err_rc);
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
		{ .name = NULL }
	};

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

	rc = yaml_lnet_peer(nid, NULL, false, -1, -1, false, detail,
			    NLM_F_DUMP, stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}
old_api:
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
	struct cYAML *err_rc = NULL, *list_rc = NULL;
	int rc;

	rc = check_cmd(peer_cmds, "peer", "list", 0, argc, argv);
	if (rc)
		return rc;

	rc = yaml_lnet_peer(NULL, NULL, false, -1, -1, true, 0, NLM_F_DUMP,
			    stdout);
	if (rc <= 0) {
		if (rc == -EOPNOTSUPP)
			goto old_api;
		return rc;
	}

old_api:
	rc = lustre_lnet_list_peer(-1, &list_rc, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);
	else if (list_rc)
		cYAML_print_tree(list_rc);

	cYAML_free_tree(err_rc);
	cYAML_free_tree(list_rc);

	return rc;
}

static int yaml_lnet_ping_display(yaml_parser_t *reply)
{
	yaml_emitter_t debug;
	bool done = false;
	int rc, rc2 = 0;
	long error = 0;

	rc = yaml_emitter_initialize(&debug);
	if (rc == 1)
		yaml_emitter_set_output_file(&debug, stdout);
	if (rc == 0)
		goto emitter_error;

	while (!done) {
		yaml_event_t event;

		rc = yaml_parser_parse(reply, &event);
		if (rc == 0)
			goto report_reply_error;

		if (event.type != YAML_SCALAR_EVENT) {
			rc = yaml_emitter_emit(&debug, &event);
			if (rc == 0)
				goto emitter_error;

			done = (event.type == YAML_DOCUMENT_END_EVENT);
			continue;
		}

		if (strcmp((char *)event.data.scalar.value, "errno") == 0) {
			rc = yaml_emitter_emit(&debug, &event);
			if (rc == 0)
				goto emitter_error;

			rc = yaml_parser_parse(reply, &event);
			if (rc == 0)
				goto report_reply_error;

			rc = parse_long((char *)event.data.scalar.value,
					&error);
			if (rc != 0)
				goto report_reply_error;

			rc = yaml_emitter_emit(&debug, &event);
			if (rc == 0)
				goto emitter_error;

			rc2 = -1;
		} else if (error != 0 &&
			   strcmp((char *)event.data.scalar.value,
				  "descr") == 0) {
			rc = yaml_emitter_emit(&debug, &event);
			if (rc == 0)
				goto emitter_error;

			rc = yaml_parser_parse(reply, &event);
			if (rc == 0)
				goto report_reply_error;

			if (strncmp((char *)event.data.scalar.value,
				    "failed to ", strlen("failed to ")) == 0) {
				char err[256];

				snprintf(err, sizeof(err), "%s: %s",
					(char *)event.data.scalar.value,
					strerror(-error));
				yaml_scalar_event_initialize(&event, NULL,
							     (yaml_char_t *)YAML_STR_TAG,
							     (yaml_char_t *)err,
							     strlen(err), 1, 0,
							     YAML_PLAIN_SCALAR_STYLE);
			}
			rc = yaml_emitter_emit(&debug, &event);
			if (rc == 0)
				goto emitter_error;

			errno = 0;
		} else {
			rc = yaml_emitter_emit(&debug, &event);
			if (rc == 0)
				goto emitter_error;
		}
	}
emitter_error:
	if (rc == 0)
		yaml_emitter_log_error(&debug, stderr);
report_reply_error:
	yaml_emitter_delete(&debug);

	return rc2 ? rc2 : rc;
}

static int yaml_lnet_ping(char *group, int timeout, struct lnet_nid *src_nid,
			  int start, int end, char **nids, int flags)
{
	struct nid_node head, *entry;
	struct nl_sock *sk = NULL;
	const char *msg = NULL;
	yaml_emitter_t output;
	yaml_parser_t reply;
	yaml_event_t event;
	int rc, i;

	/* Create Netlink emitter to send request to kernel */
	sk = nl_socket_alloc();
	if (!sk)
		return -EOPNOTSUPP;

	/* Setup parser to receive Netlink packets */
	rc = yaml_parser_initialize(&reply);
	if (rc == 0) {
		nl_socket_free(sk);
		return -EOPNOTSUPP;
	}

	rc = yaml_parser_set_input_netlink(&reply, sk, false);
	if (rc == 0) {
		msg = yaml_parser_get_reader_error(&reply);
		goto free_reply;
	}

	/* Create Netlink emitter to send request to kernel */
	rc = yaml_emitter_initialize(&output);
	if (rc == 0) {
		msg = "failed to initialize emitter";
		goto free_reply;
	}

	rc = yaml_emitter_set_output_netlink(&output, sk, LNET_GENL_NAME,
					     LNET_GENL_VERSION, LNET_CMD_PING,
					     flags);
	if (rc == 0)
		goto emitter_error;

	yaml_emitter_open(&output);
	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)group,
				     strlen(group), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	if (timeout != 1000 || (src_nid && nid_addr_is_set(src_nid))) {
		if (src_nid) {
			char *src_nidstr = libcfs_nidstr(src_nid);

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"source",
						     strlen("source"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)src_nidstr,
						     strlen(src_nidstr), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		}

		if (timeout != 1000) {
			char time[23];

			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_STR_TAG,
						     (yaml_char_t *)"timeout",
						     strlen("timeout"), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;

			snprintf(time, sizeof(time), "%u", timeout);
			yaml_scalar_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_INT_TAG,
						     (yaml_char_t *)time,
						     strlen(time), 1, 0,
						     YAML_PLAIN_SCALAR_STYLE);
			rc = yaml_emitter_emit(&output, &event);
			if (rc == 0)
				goto emitter_error;
		}
	}

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)"nids",
				     strlen("nids"), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_sequence_start_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_SEQ_TAG,
					     1, YAML_FLOW_SEQUENCE_STYLE);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	NL_INIT_LIST_HEAD(&head.children);
	nl_init_list_head(&head.list);
	for (i = start; i < end; i++) {
		rc = lustre_lnet_parse_nid_range(&head, nids[i], &msg);
		if (rc < 0) {
			lustre_lnet_free_list(&head);
			yaml_emitter_delete(&output);
			errno = rc;
			rc = 0;
			goto free_reply;
		}
	}

	if (nl_list_empty(&head.children))
		goto skip_nids;

	nl_list_for_each_entry(entry, &head.children, list) {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)entry->nidstr,
					     strlen(entry->nidstr), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&output, &event);
		if (rc == 0)
			goto emitter_error;
	}
skip_nids:
	yaml_sequence_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	yaml_document_end_event_initialize(&event, 0);
	rc = yaml_emitter_emit(&output, &event);
	if (rc == 0)
		goto emitter_error;

	rc = yaml_emitter_close(&output);
emitter_error:
	if (rc == 0) {
		yaml_emitter_log_error(&output, stderr);
		rc = -EINVAL;
	} else {
		rc = yaml_lnet_ping_display(&reply);
		if (rc == 0)
			msg = yaml_parser_get_reader_error(&reply);
	}
	yaml_emitter_delete(&output);
free_reply:
	if (rc == 0) {
		yaml_lnet_print_error(-1, group, msg);
		rc = -EINVAL;
	}

	yaml_parser_delete(&reply);
	nl_socket_free(sk);

	return rc == 1 ? 0 : rc;
}

static int jt_ping(int argc, char **argv)
{
	struct cYAML *err_rc = NULL;
	struct cYAML *show_rc = NULL;
	struct lnet_nid src = { };
	int timeout = 1000;
	int rc = 0, opt;
	char *src_nidstr = NULL;
	const char *const short_options = "hs:t:";
	const struct option long_options[] = {
		{ .name = "help",	.has_arg = no_argument,		.val = 'h' },
		{ .name = "timeout",	.has_arg = required_argument,	.val = 't' },
		{ .name = "source",	.has_arg = required_argument,	.val = 's' },
		{ .name = NULL }
	};

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 's':
			src_nidstr = optarg;
			rc = libcfs_strnid(&src, src_nidstr);
			break;
		case 't':
			timeout = 1000 * atol(optarg);
			break;
		case 'h':
			printf("ping nid[,nid,...]\n"
			       "\t --source: source nid\n"
			       "\t --timeout: ping timeout\n"
			       "\t --help: display this help\n");
			return 0;
		default:
			return 0;
		}
	}
	if (rc < 0)
		return rc;

	rc = yaml_lnet_ping("ping", timeout, &src, optind, argc, argv,
			    NLM_F_DUMP);
	if (rc <= 0) {
		if (rc != -EOPNOTSUPP)
			return rc;
	}

	for (; optind < argc; optind++)
		rc = lustre_lnet_ping_nid(argv[optind], src_nidstr, timeout, -1,
					  &show_rc, &err_rc);

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
	int flags = NLM_F_CREATE;
	int force = 0;
	int rc = 0, opt;
	const char *const short_options = "fh";
	const struct option long_options[] = {
		{ .name = "force",	.has_arg = no_argument,	.val = 'f' },
		{ .name = "help",	.has_arg = no_argument,	.val = 'h' },
		{ .name = NULL }
	};

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'f':
			/* BSD treats NLM_F_CREATE | NLM_F_EXCL as an add */
			flags |= NLM_F_EXCL;
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

	if (optind == argc) {
		printf("Missing nid argument\n");
		return -1;
	}

	rc = yaml_lnet_ping("discover", 1000, NULL, optind, argc, argv,
			    flags);
	if (rc <= 0) {
		if (rc != -EOPNOTSUPP)
			return rc;
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
			if (rc != 0 || priority < 0) {
				printf("Invalid priority \"%s\"\n", optarg);
				return -EINVAL;
			}
			action_type = "priority";
			udsp_action.udsp_priority = priority;
			break;
		case 'i':
			rc = parse_long(optarg, &idx);
			if (rc != 0 || idx < 0) {
				printf("Invalid index \"%s\"\n", optarg);
				return -EINVAL;
			}
			break;
		case '?':
			print_help(udsp_cmds, "udsp", "add");
		default:
			return 0;
		}
	}

	if (!(src || dst || rte)) {
		print_help(udsp_cmds, "udsp", "add");
		return 0;
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
	long int idx = -2;
	int opt, rc = 0;
	bool all = false;

	const char *const short_options = "ai:";
	static const struct option long_options[] = {
	{ .name = "all",	.has_arg = no_argument, .val = 'a' },
	{ .name = "idx",	.has_arg = required_argument, .val = 'i' },
	{ .name = NULL } };

	rc = check_cmd(udsp_cmds, "udsp", "del", 0, argc, argv);
	if (rc)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			all = true;
			break;
		case 'i':
			rc = parse_long(optarg, &idx);
			if (rc != 0 || idx < -1) {
				printf("Invalid index \"%s\"\n", optarg);
				return -EINVAL;
			}
			break;
		case '?':
			print_help(udsp_cmds, "udsp", "del");
		default:
			return 0;
		}
	}

	if (all && idx != -2) {
		printf("Cannot combine --all with --idx\n");
		return -EINVAL;
	} else if (all) {
		idx = -1;
	} else if (idx == -2) {
		printf("Must specify --idx or --all\n");
		return -EINVAL;
	}

	rc = lustre_lnet_del_udsp(idx, -1, &err_rc);
	if (rc != LUSTRE_CFG_RC_NO_ERR)
		cYAML_print_tree2file(stderr, err_rc);

	cYAML_free_tree(err_rc);

	return rc;
}

static int
fault_attr_nid_parse(char *str, lnet_nid_t *nid_p)
{
	lnet_nid_t nid;
	__u32 net;
	int rc = 0;

	/* NB: can't support range ipaddress except * and *@net */
	if (strlen(str) > 2 && str[0] == '*' && str[1] == '@') {
		net = libcfs_str2net(str + 2);
		if (net == LNET_NET_ANY)
			goto failed;

		nid = LNET_MKNID(net, LNET_NIDADDR(LNET_NID_ANY));
	} else {
		rc = libcfs_str2anynid(&nid, str);
		if (!rc)
			goto failed;
	}

	*nid_p = nid;
	return 0;
failed:
	fprintf(stderr, "Invalid NID : %s\n", str);
	return -1;
}

static int
fault_attr_health_error_parse(char *error, __u32 *mask)
{
	if (!strcasecmp(error, "local_interrupt")) {
		*mask |= HSTATUS_LOCAL_INTERRUPT_BIT;
		return 0;
	}
	if (!strcasecmp(error, "local_dropped")) {
		*mask |= HSTATUS_LOCAL_DROPPED_BIT;
		return 0;
	}
	if (!strcasecmp(error, "local_aborted")) {
		*mask |= HSTATUS_LOCAL_ABORTED_BIT;
		return 0;
	}
	if (!strcasecmp(error, "local_no_route")) {
		*mask |= HSTATUS_LOCAL_NO_ROUTE_BIT;
		return 0;
	}
	if (!strcasecmp(error, "local_error")) {
		*mask |= HSTATUS_LOCAL_ERROR_BIT;
		return 0;
	}
	if (!strcasecmp(error, "local_timeout")) {
		*mask |= HSTATUS_LOCAL_TIMEOUT_BIT;
		return 0;
	}
	if (!strcasecmp(error, "remote_error")) {
		*mask |= HSTATUS_REMOTE_ERROR_BIT;
		return 0;
	}
	if (!strcasecmp(error, "remote_dropped")) {
		*mask |= HSTATUS_REMOTE_DROPPED_BIT;
		return 0;
	}
	if (!strcasecmp(error, "remote_timeout")) {
		*mask |= HSTATUS_REMOTE_TIMEOUT_BIT;
		return 0;
	}
	if (!strcasecmp(error, "network_timeout")) {
		*mask |= HSTATUS_NETWORK_TIMEOUT_BIT;
		return 0;
	}
	if (!strcasecmp(error, "random")) {
		*mask = HSTATUS_RANDOM;
		return 0;
	}

	return -1;
}

static int jt_add_fault(int argc, char **argv)
{
	const char *const short_options = "r:s:d:o:r:i:l:p:m:e:nx";
	static const struct option long_options[] = {
		{ .name = "rule_type",	.has_arg = required_argument, .val = 't' },
		{ .name = "source",	.has_arg = required_argument, .val = 's' },
		{ .name = "dest",	.has_arg = required_argument, .val = 'd' },
		{ .name = "rate",	.has_arg = required_argument, .val = 'r' },
		{ .name = "interval",	.has_arg = required_argument, .val = 'i' },
		{ .name = "random",	.has_arg = no_argument,       .val = 'n' },
		{ .name = "latency",	.has_arg = required_argument, .val = 'l' },
		{ .name = "portal",	.has_arg = required_argument, .val = 'p' },
		{ .name = "message",	.has_arg = required_argument, .val = 'm' },
		{ .name = "health_error", .has_arg = required_argument, .val = 'e' },
		{ .name = "local_nid",	.has_arg = required_argument, .val = 'o' },
		{ .name = "drop_all",	.has_arg = no_argument, .val = 'x' },
		{ .name = NULL }
	};
	int opc = 0, opt, rc2, rc = 0;
	struct lnet_fault_attr attr;
	yaml_document_t results;
	yaml_emitter_t debug;

	rc = check_cmd(fault_cmds, "fault", "add", 2, argc, argv);
	if (rc < 0)
		return rc;

	attr.fa_local_nid = LNET_NID_ANY;

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 't':
			if (strcmp(optarg, "delay") == 0)
				opc = LNET_CTL_DELAY_ADD;
			else if (strcmp(optarg, "drop") == 0)
				opc = LNET_CTL_DROP_ADD;
			else
				rc = -EINVAL;
			break;

		case 'o':
			rc2 = fault_attr_nid_parse(optarg, &attr.fa_local_nid);
			if (rc2 < 0 && !rc)
				rc = rc2;
			break;

		case 's': /* source NID/NET */
			rc2 = fault_attr_nid_parse(optarg, &attr.fa_src);
			if (rc2 < 0 && !rc)
				rc = rc2;
			break;

		case 'd': /* dest NID/NET */
			rc2 = fault_attr_nid_parse(optarg, &attr.fa_dst);
			if (rc2 < 0 && !rc)
				rc = rc2;
			break;

		case 'r': /* drop rate */
			if (opc == LNET_CTL_DROP_ADD)
				attr.u.drop.da_rate = strtoul(optarg, NULL, 0);
			else
				attr.u.delay.la_rate = strtoul(optarg, NULL, 0);
			break;

		case 'e':
			if (opc == LNET_CTL_DROP_ADD) {
				rc2 = fault_attr_health_error_parse(optarg,
								    &attr.u.drop.da_health_error_mask);
				if (rc2 < 0 && !rc)
					rc = rc2;
			}
			break;

		case 'x':
			if (opc == LNET_CTL_DROP_ADD)
				attr.u.drop.da_drop_all = true;
			break;

		case 'n':
			if (opc == LNET_CTL_DROP_ADD)
				attr.u.drop.da_random = true;
			break;

		case 'i': /* time interval (# seconds) for message drop */
			if (opc == LNET_CTL_DROP_ADD)
				attr.u.drop.da_interval = strtoul(optarg,
								  NULL, 0);
			else
				attr.u.delay.la_interval = strtoul(optarg,
								   NULL, 0);
			break;
		default:
			return 0;
		}
	}
	if (rc < 0)
		return rc;

	rc = yaml_lnet_fault_rule(&results, opc, NULL, NULL, NULL, NULL);
	if (rc < 0)
		return rc;

	rc = yaml_emitter_initialize(&debug);
	if (rc == 0)
		return -EINVAL;

	yaml_emitter_set_indent(&debug, LNET_DEFAULT_INDENT);
	yaml_emitter_set_output_file(&debug, stdout);
	rc = yaml_emitter_dump(&debug, &results);

	yaml_emitter_delete(&debug);
	yaml_document_delete(&results);

	return rc == 0 ? -EINVAL : 0;
}

static int jt_del_fault(int argc, char **argv)
{
	const char *const short_options = "t:";
	static const struct option long_options[] = {
		{ .name = "rule_type",	.has_arg = required_argument, .val = 't' },
		{ .name = "source", .has_arg = required_argument, .val = 's' },
		{ .name = "dest",   .has_arg = required_argument, .val = 'd' },
		{ .name = NULL }
	};
	struct lnet_fault_attr attr;
	yaml_document_t results;
	yaml_emitter_t debug;
	int opc = 0, opt, rc;

	rc = check_cmd(fault_cmds, "fault", "del", 2, argc, argv);
	if (rc < 0)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 't':
			if (strcmp(optarg, "delay") == 0)
				opc = LNET_CTL_DELAY_DEL;
			else if (strcmp(optarg, "drop") == 0)
				opc = LNET_CTL_DROP_DEL;
			else
				rc = -EINVAL;
			break;
		case 's': /* source NID/NET */
			rc = fault_attr_nid_parse(optarg, &attr.fa_src);
			break;

		case 'd': /* dest NID/NET */
			rc = fault_attr_nid_parse(optarg, &attr.fa_dst);
			break;
		default:
			return 0;
		}
	}
	if (rc < 0)
		return rc;

	rc = yaml_lnet_fault_rule(&results, opc, NULL, NULL, NULL, NULL);
	if (rc < 0)
		return rc;

	rc = yaml_emitter_initialize(&debug);
	if (rc == 0)
		return -EINVAL;

	yaml_emitter_set_indent(&debug, LNET_DEFAULT_INDENT);
	yaml_emitter_set_output_file(&debug, stdout);
	rc = yaml_emitter_dump(&debug, &results);
	yaml_emitter_delete(&debug);
	yaml_document_delete(&results);

	return rc == 0 ? -EINVAL : 0;
}

static int jt_reset_fault(int argc, char **argv)
{
	const char *const short_options = "r:";
	static const struct option long_options[] = {
		{ .name = "rule_type",	.has_arg = required_argument, .val = 't' },
		{ .name = NULL }
	};
	yaml_document_t results;
	yaml_emitter_t debug;
	int opc = 0, opt, rc;

	rc = check_cmd(fault_cmds, "fault", "reset", 2, argc, argv);
	if (rc < 0)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 't':
			if (strcmp(optarg, "delay") == 0)
				opc = LNET_CTL_DELAY_RESET;
			else if (strcmp(optarg, "drop") == 0)
				opc = LNET_CTL_DROP_RESET;
			else
				rc = -EINVAL;
			break;
		default:
			return 0;
		}
	}
	if (rc < 0)
		return rc;

	rc = yaml_lnet_fault_rule(&results, opc, NULL, NULL, NULL, NULL);
	if (rc < 0)
		return rc;

	rc = yaml_emitter_initialize(&debug);
	if (rc == 0)
		return -EINVAL;

	yaml_emitter_set_indent(&debug, LNET_DEFAULT_INDENT);
	yaml_emitter_set_output_file(&debug, stdout);
	rc = yaml_emitter_dump(&debug, &results);
	yaml_emitter_delete(&debug);
	yaml_document_delete(&results);

	return rc == 0 ? -EINVAL : 0;
}

int jt_show_fault(int argc, char **argv)
{
	const char *const short_options = "t:";
	static const struct option long_options[] = {
		{ .name = "rule_type",	.has_arg = required_argument, .val = 't' },
		{ .name = NULL }
	};
	yaml_document_t results;
	yaml_emitter_t debug;
	int opc = 0, opt, rc;

	rc = check_cmd(fault_cmds, "fault", "show", 2, argc, argv);
	if (rc < 0)
		return rc;

	while ((opt = getopt_long(argc, argv, short_options,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 't':
			if (strcmp(optarg, "delay") == 0)
				opc = LNET_CTL_DELAY_LIST;
			else if (strcmp(optarg, "drop") == 0)
				opc = LNET_CTL_DROP_LIST;
			else
				rc = -EINVAL;
			break;
		default:
			rc = -EINVAL;
		}
	}
	if (rc < 0)
		return rc;

	rc = yaml_lnet_fault_rule(&results, opc, NULL, NULL, NULL, NULL);
	if (rc < 0)
		return rc;

	rc = yaml_emitter_initialize(&debug);
	if (rc == 0)
		return -EINVAL;

	yaml_emitter_set_indent(&debug, LNET_DEFAULT_INDENT);
	yaml_emitter_set_output_file(&debug, stdout);
	rc = yaml_emitter_dump(&debug, &results);

	yaml_emitter_delete(&debug);
	yaml_document_delete(&results);

	return rc == 0 ? -EINVAL : 0;
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

	return cfs_parser(argc, argv, cmd_list);
}
