/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Robert Read <rread@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <portals/api-support.h>
#include <portals/ptlctl.h>
#include "obdctl.h"
#include "parser.h"

static int jt_quit(int argc, char **argv) {
        Parser_quit(argc, argv);
        return 0;
}

static int jt_noop(int argc, char **argv) {
        return 0;
}

static int jt_opt_ignore_errors(int argc, char **argv) {
        Parser_ignore_errors(1);
        return 0;
}

command_t cmdlist[] = {
        /* Metacommands */
        {"--device", jt_opt_device, 0,
         "run <command> after connecting to device <devno>\n"
         "--device <devno> <command [args ...]>"},
        {"--threads", jt_opt_threads, 0,
         "run <threads> separate instances of <command> on device <devno>\n"
         "--threads <threads> <verbose> <devno> <command [args ...]>"},
        {"--ignore_errors", jt_opt_ignore_errors, 0,
         "ignore errors that occur during script processing\n"
         "--ignore_errors"},
        {"ignore_errors", jt_opt_ignore_errors, 0,
         "ignore errors that occur during script processing\n"
         "ignore_errors"},
        {"dump", jt_ioc_dump, 0, "usage: dump file, save ioctl buffer to file"},

        /* Network configuration commands */
        {"==== network config ====", jt_noop, 0, "network config"},
        {"--net", jt_opt_net, 0, "run <command> after setting network to <net>\n"
         "usage: --net <tcp/elan/myrinet/scimac> <command>"},
        {"network", jt_ptl_network, 0, "commands that follow apply to net\n"
         "usage: network <tcp/elan/myrinet/scimac>"},
        {"autoconn_list", jt_ptl_print_autoconnects, 0, "print autoconnect entries\n"
         "usage: print_autoconns"},
        {"add_autoconn", jt_ptl_add_autoconnect, 0, "add an autoconnect entry\n"
         "usage: add_autoconn <nid> <host> <port> [ixse]"},
        {"del_autoconn", jt_ptl_del_autoconnect, 0, "remove an autoconnect entry\n"
         "usage: del_autoconn [<nid>] [<host>] [ks]"},
        {"conn_list", jt_ptl_print_connections, 0, "connect to a remote nid\n"
         "usage: print_conns"},
        {"connect", jt_ptl_connect, 0, "connect to a remote nid\n"
         "usage: connect <host> <port> [ix]"},
        {"disconnect", jt_ptl_disconnect, 0, "disconnect from a remote nid\n"
         "usage: disconnect [<nid>]"},
        {"active_tx", jt_ptl_print_active_txs, 0, "print active transmits (no args)\n"
         "usage: active_tx"},
        {"mynid", jt_ptl_mynid, 0, "inform the socknal of the local nid. "
         "The nid defaults to hostname for tcp networks and is automatically "
         "setup for elan/myrinet/scimac networks.\n"
         "usage: mynid [<nid>]"},
        {"shownid", jt_ptl_shownid, 0, "print the local NID\n"
         "usage: shownid"},
        {"add_uuid", jt_obd_add_uuid, 0, "associate a UUID with a nid\n"
         "usage: add_uuid <uuid> <nid> <net_type>"},
        {"close_uuid", jt_obd_close_uuid, 0, "disconnect a UUID\n"
         "usage: close_uuid <uuid> <net-type>)"},
        {"del_uuid", jt_obd_del_uuid, 0, "delete a UUID association\n"
         "usage: del_uuid <uuid>"},
        {"add_route", jt_ptl_add_route, 0,
         "add an entry to the portals routing table\n"
         "usage: add_route <gateway> <target> [<target>]"},
        {"del_route", jt_ptl_del_route, 0,
         "delete the route via the given gateway to the given targets from the portals routing table\n"
         "usage: del_route <gateway> [<target>] [<target>]"},
        {"set_route", jt_ptl_notify_router, 0,
         "enable/disable routes via the given gateway in the portals routing table\n"
         "usage: set_route <gateway> <up/down> [<time>]"},
        {"route_list", jt_ptl_print_routes, 0, "print the portals routing table\n"
         "usage: route_list"},
        {"recv_mem", jt_ptl_rxmem, 0, "set socket receive buffer size, "
         "if size is omited the current size is reported.\n"
         "usage: recv_mem [size]"},
        {"send_mem", jt_ptl_txmem, 0, "set socket send buffer size, "
         "if size is omited the current size is reported.\n"
         "usage: send_mem [size]"},
        {"nagle", jt_ptl_nagle, 0, "enable/disable nagle, omitting the "
         "argument will cause the current nagle setting to be reported.\n"
         "usage: nagle [on/off]"},
        {"fail", jt_ptl_fail_nid, 0, "fail/restore communications.\n"
         "Omitting the count means indefinitely, 0 means restore, "
         "otherwise fail 'count' messages.\n"
         "usage: fail nid|_all_ [count]"},

        /* Device selection commands */
        {"=== device selection ===", jt_noop, 0, "device selection"},
        {"newdev", jt_obd_newdev, 0, "create a new device\n"
         "usage: newdev"},
        {"device", jt_obd_device, 0,
         "set current device to <%name|$name|devno>\n"
         "usage: device <%name|$name|devno>"},
        {"device_list", jt_obd_list, 0, "show all devices\n"
         "usage: device_list"},
        {"lustre_build_version", jt_get_version, 0,
         "print the build version of lustre\n"
         "usage: lustre_build_version"},

        /* Device configuration commands */
        {"==== device config =====", jt_noop, 0, "device config"},
        {"attach", jt_obd_attach, 0,
         "set the type of the current device (with <name> and <uuid>)\n"
         "usage: attach type [name [uuid]]"},
        {"setup", jt_obd_setup, 0,
         "type specific device configuration information\n"
         "usage: setup <args...>"},
        {"cleanup", jt_obd_cleanup, 0, "cleanup previously setup device\n"
         "usage: cleanup [force | failover]"},
        {"detach", jt_obd_detach, 0,
         "remove driver (and name and uuid) from current device\n"
         "usage: detach"},
        {"lov_setconfig", jt_obd_lov_setconfig, 0,
         "write lov configuration to an mds device\n"
         "usage: lov_setconfig lov-uuid stripe-count stripe-size offset pattern UUID1 [UUID2 ...]"},
        {"lov_getconfig", jt_obd_lov_getconfig, 0,
         "read lov configuration from an mds device\n"
         "usage: lov_getconfig lov-uuid"},

        /* Device operations */
        {"=== device operations ==", jt_noop, 0, "device operations"},
        {"probe", jt_obd_connect, 0,
         "build a connection handle to a device.  This command is used to "
         "suspend configuration until lctl has ensured that the mds and osc "
         "services are available.  This is to avoid mount failures in a "
         "rebooting cluster.\n"
         "usage: probe [timeout]"},
        {"close", jt_obd_disconnect, 0,
         "close the connection handle\n"
         "usage: close"},
        {"getattr", jt_obd_getattr, 0,
         "get attribute for OST object <objid>\n"
         "usage: getattr <objid>"},
        {"setattr", jt_obd_setattr, 0,
         "set mode attribute for OST object <objid>\n"
         "usage: setattr <objid> <mode>"},
         {"create", jt_obd_create, 0,
         "create <num> OST objects (with <mode>)\n"
         "usage: create [num [mode [verbose [lsm data]]]]"},
        {"destroy", jt_obd_destroy, 0,
         "destroy OST object <objid> [num [verbose]]\n"
         "usage: destroy <num> objects, starting at objid <objid>"},
        {"test_getattr", jt_obd_test_getattr, 0,
         "do <num> getattrs (on OST object <objid> (objid+1 on each thread))\n"
         "usage: test_getattr <num> [verbose [[t]objid]]"},
        {"test_brw", jt_obd_test_brw, 0,
         "do <num> bulk read/writes (<npages> per I/O, on OST object <objid>)\n"
         "usage: test_brw [t]<num> [write [verbose [npages [[t]objid]]]]"},
        {"get_stripe", jt_obd_get_stripe, 0,
         "show stripe info for an echo client object\n"
         "usage: get_stripe objid\n"},
        {"set_stripe", jt_obd_set_stripe, 0,
         "set stripe info for an echo client object\n"
         "usage: set_stripe objid[=width!count[@offset][:id:id...]\n"},
        {"unset_stripe", jt_obd_unset_stripe, 0,
         "unset stripe info for an echo client object\n"
         "usage: unset_stripe objid\n"},
        {"test_ldlm", jt_obd_test_ldlm, 0,
         "perform lock manager test\n"
         "usage: test_ldlm"},
        {"ldlm_regress_start", jt_obd_ldlm_regress_start, 0,
         "start lock manager stress test\n"
         "usage: ldlm_regress_start [numthreads [refheld [numres [numext]]]]"},
        {"ldlm_regress_stop", jt_obd_ldlm_regress_stop, 0,
         "stop lock manager stress test (no args)\n"},
        {"dump_ldlm", jt_obd_dump_ldlm, 0,
         "dump all lock manager state (no args)"},
        {"activate", jt_obd_activate, 0, "activate an import\n"},
        {"deactivate", jt_obd_deactivate, 0, "deactivate an import\n"},
        {"recover", jt_obd_recover, 0, "usage: recover [<connection UUID>]"},
        {"lookup", jt_obd_mdc_lookup, 0, "usage: lookup <directory> <file>"},
        {"notransno", jt_obd_no_transno, 0,
         "disable sending of committed-transno updates\n"},
        {"readonly", jt_obd_set_readonly, 0,
         "disable writes to the underlying device\n"},
        {"abort_recovery", jt_obd_abort_recovery, 0,
         "abort recovery on MDS device\n"},
        {"mount_option", jt_obd_mount_option, 0,
         "dump mount options to file\n"},

        /* Debug commands */
        {"======== debug =========", jt_noop, 0, "debug"},
        {"debug_daemon", jt_dbg_debug_daemon, 0,
         "debug daemon control and dump to a file"
         "usage: debug_daemon [start file <#MB>|stop|pause|continue]"},
        {"debug_kernel", jt_dbg_debug_kernel, 0,
         "get debug buffer and dump to a file"
         "usage: debug_kernel [file] [raw]"},
        {"dk", jt_dbg_debug_kernel, 0,
         "get debug buffer and dump to a file"
         "usage: dk [file] [raw]"},
        {"debug_file", jt_dbg_debug_file, 0,
         "read debug buffer from input and dump to output"
         "usage: debug_file <input> [output] [raw]"},
        {"clear", jt_dbg_clear_debug_buf, 0, "clear kernel debug buffer\n"
         "usage: clear"},
        {"mark", jt_dbg_mark_debug_buf, 0,"insert marker text in kernel debug buffer\n"
         "usage: mark <text>"},
        {"filter", jt_dbg_filter, 0, "filter message type\n"
         "usage: filter <subsystem id/debug mask>"},
        {"show", jt_dbg_show, 0, "show message type\n"
         "usage: show <subsystem id/debug mask>"},
        {"debug_list", jt_dbg_list, 0, "list subsystem and debug types\n"
         "usage: debug_list <subs/types>"},
        {"modules", jt_dbg_modules, 0,
         "provide gdb-friendly module information\n"
         "usage: modules <path>"},
        {"panic", jt_dbg_panic, 0, "force the kernel to panic\n"
         "usage: panic"},
        {"lwt", jt_ptl_lwt, 0,
         "light-weight tracing\n"
         "usage: lwt start\n"
         "       lwt stop [file]"},
                
        /* User interface commands */
        {"======= control ========", jt_noop, 0, "control commands"},
        {"help", Parser_help, 0, "help"},
        {"exit", jt_quit, 0, "quit"},
        {"quit", jt_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};



int main(int argc, char **argv)
{
        int rc;

        setlinebuf(stdout);

        ptl_initialize(argc, argv);
        if (obd_initialize(argc, argv) < 0)
                exit(2);
        if (dbg_initialize(argc, argv) < 0)
                exit(3);

        Parser_init("lctl > ", cmdlist);

        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                rc = Parser_commands();
        }

        obd_cleanup(argc, argv);
        return rc;
}

