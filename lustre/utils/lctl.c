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

command_t cmdlist[] = {
        /* Metacommands */
        {"--device", jt_opt_device, 0, "--device <devno> <command [args ...]>"},
        {"--threads", jt_opt_threads, 0,
                "--threads <threads> <devno> <command [args ...]>"},

        /* Network configuration commands */
        {"==== network config ====", jt_noop, 0, "network config"},
        {"network", jt_ptl_setup, 0, "commands that follow apply to net\n"
         "usage: network <tcp/elan/myrinet>"},       
        {"connect", jt_ptl_connect, 0, "connect to a remote nid\n"
         "usage: connect [[<hostname> <port>] | <elan id>]"},
        {"disconnect", jt_ptl_disconnect, 0, "disconnect from a remote nid\n"
         "usage: disconnect <nid>"},
        {"mynid", jt_ptl_mynid, 0, "inform the socknal of the local nid. "
         "The nid defaults to hostname for tcp networks and is automatically "
         "setup for elan/myrinet networks.\n"
         "usage: mynid [nid]"},
        {"add_uuid", jt_ptl_add_uuid, 0, "associate a uuid with a nid\n"
         "usage: add_uuid <uuid> <nid>"},
        {"del_uuid", jt_ptl_del_uuid, 0, "delete a uuid association\n"
         "usage: del_uuid <uuid>"},
        {"add_route", jt_ptl_add_route, 0,
         "add an entry to the routing table\n"
         "usage: add_route <gateway> <target> [target]"},
        {"del_route", jt_ptl_del_route, 0,
         "delete an entry from the routing table\n"
         "usage: del_route <target>"},
        {"route_list", jt_ptl_print_routes, 0, "print the routing table\n"
         "usage: route_list"},
        {"recv_mem", jt_ptl_rxmem, 0, "set socket receive buffer size, "
         "if size is omited the current size is reported.\n"
         "usage: recv_mem [size]"},
        {"send_mem", jt_ptl_txmem, 0, "set socket send buffer size, "
         "if size is omited the current size is reported.\n"
         "usage: send_mem [size]"},
        {"nagle", jt_ptl_nagle, 0, "enable/disable nagle, omiting the "
         "argument will cause the current nagle setting to be reported.\n" 
         "usage: nagle [on/off]"},       
                
        /* Device selection commands */
        {"=== device selection ===", jt_noop, 0, "device selection"},
        {"newdev", jt_obd_newdev, 0, "create a new device\n"
         "usage: newdev"},
#if 0
        {"uuid2dev", jt_obd_uuid2dev, 0,
         "find a uuid and make it the current device\n"
         "usage: uuid2dev <uuid>"},
#endif
        {"name2dev", jt_obd_name2dev, 0,
         "find a name and make it the current device\n"
         "usage: name2dev <name>"},
        {"device", jt_obd_device, 0, "set current device to devno\n"
         "usage: device <devno>"},
        {"device_list", jt_obd_list, 0, "show all devices\n"
         "usage: device_list"},
         
        /* Device configuration commands */
        {"==== device config =====", jt_noop, 0, "device config"},
        {"attach", jt_obd_attach, 0, "name and type the device\n"
         "usage: attach type [name [uuid]]"},
        {"setup", jt_obd_setup, 0,
         "type specific device configuration information\n"
         "usage: setup <args...>"},
        {"cleanup", jt_obd_cleanup, 0, "cleanup setup\n"
         "usage: cleanup"},
        {"detach", jt_obd_detach, 0, "un-name a device\n"
         "usage: detach"},
        {"lovconfig", jt_obd_lov_config, 0,
         "write lov configuration to an mds device\n"
         "usage: lovconfig lov-uuid stripe-count stripe-size offset pattern UUID1 [UUID2 ...]"},

        /* Device operations */
        {"=== device operations ==", jt_noop, 0, "device operations"},
        {"probe", jt_obd_connect, 0,
         "build a connection handle to a device.  This command is used too "
         "suspend configuration until lctl has ensured that the mds and osc "
         "services are available.  This is to avoid mount failures in a "
         "rebooting cluster.\n"
         "usage: probe [<timeout]"},
        {"close", jt_obd_disconnect, 0, "close the connection handle\n"
         "usage: close"},
        {"getattr", jt_obd_getattr, 0, "get attribute for id\n"
         "usage: getattr <id>"},
        {"setattr", jt_obd_setattr, 0, "set attribute for id\n"
         "usage: setattr <id> <mode>"},
        {"test_getattr", jt_obd_test_getattr, 0,
         "perform count number of getattr's\n"
         "usage: test_getattr <count> [verbose]"},
        {"test_brw", jt_obd_test_brw, 0,
         "perform count number of bulk read/writes\n"
         "usage: test_brw <count> [write [verbose [pages [obdos]]]]"},
        {"test_ldlm", jt_obd_test_ldlm, 0, "perform lock manager test\n"
         "usage: test_ldlm"},
        {"ldlm_regress_start", jt_obd_ldlm_regress_start, 0,
         "start lock manager stress test (usage: ldlm_regress_start "
         "[numthreads])\n"},
        {"ldlm_regress_stop", jt_obd_ldlm_regress_stop, 0,
         "stop lock manager stress test (no args)\n"},
        {"dump_ldlm", jt_obd_dump_ldlm, 0,
         "dump all lock manager state (no args)"},

#if 0
        {"create", jt_create, 0, "create [count [mode [verbose]]]"},
        {"destroy", jt_destroy, 0, "destroy <id>"},
        {"newconn", jt_newconn, 0, "newconn [newuuid]"},
#endif
        /* Debug commands */
        {"======== debug =========", jt_noop, 0, "debug"},
        {"debug_kernel", jt_dbg_debug_kernel, 0,
         "get debug buffer and dump to a file"
         "usage: debug_kernel [file] [raw]"},
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

        if (ptl_initialize(argc, argv) < 0)
                exit(1);
        if (obd_initialize(argc, argv) < 0)
                exit(2);
        if (dbg_initialize(argc, argv) < 0)
                exit(3);
        
        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                Parser_init("lctl > ", cmdlist);
                rc = Parser_commands();
        }

        obd_cleanup(argc, argv);
        return rc;
}

