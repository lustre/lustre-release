/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <lnet/api-support.h>
#include <lnet/lnetctl.h>

#include "parser.h"


command_t list[] = {
        {"network", jt_ptl_network, 0,"select/configure network (args: up|down|LND name)"},
        {"net", jt_ptl_network, 0,"select/configure network (args: up|down|LND name)"},
        {"list_nids", jt_ptl_list_nids, 0,"list local NIDs"},
        {"which_nid", jt_ptl_which_nid, 0,"select the closest NID"},
        {"print_interfaces", jt_ptl_print_interfaces, 0, "print interface entries (no args)"},
        {"add_interface", jt_ptl_add_interface, 0, "add interface entry (args: ip [netmask])"},
        {"del_interface", jt_ptl_del_interface, 0, "delete interface entries (args: [ip])"},
        {"print_peers", jt_ptl_print_peers, 0, "print peer entries (no args)"},
        {"add_peer", jt_ptl_add_peer, 0, "add peer entry (args: nid host port)"},
        {"del_peer", jt_ptl_del_peer, 0, "delete peer entry (args: [nid] [host])"},
        {"print_conns", jt_ptl_print_connections, 0, "print connections (no args)"},
        {"disconnect", jt_ptl_disconnect, 0, "disconnect from a remote nid (args: [nid] [host]"},
        {"push", jt_ptl_push_connection, 0, "flush connection to a remote nid (args: [nid]"},
        {"active_tx", jt_ptl_print_active_txs, 0, "print active transmits (no args)"},
        {"testping", jt_ptl_ping_test, 0, "do a ping test (args: nid [count] [size] [timeout])"},
        {"ping", jt_ptl_ping, 0, "ping (args: nid [timeout] [pid])"},
        {"mynid", jt_ptl_mynid, 0, "inform the socknal of the local NID (args: [hostname])"},
        {"add_route", jt_ptl_add_route, 0, 
         "add an entry to the routing table (args: gatewayNID targetNID [targetNID])"},
        {"del_route", jt_ptl_del_route, 0, 
         "delete all routes via a gateway from the routing table (args: gatewayNID"},
        {"set_route", jt_ptl_notify_router, 0, 
         "enable/disable a route in the routing table (args: gatewayNID up/down [time]"},
        {"print_routes", jt_ptl_print_routes, 0, "print the routing table (args: none)"},
        {"dump", jt_ioc_dump, 0, "usage: dump file, save ioctl buffer to file"},
        {"fail", jt_ptl_fail_nid, 0, "usage: fail nid|_all_ [count]"},
        {"testprotocompat", jt_ptl_testprotocompat, 0, "usage: testprotocompat count"},
        {"help", Parser_help, 0, "help"},
        {"exit", Parser_quit, 0, "quit"},
        {"quit", Parser_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};

int main(int argc, char **argv)
{
        if (ptl_initialize(argc, argv) < 0)
                exit(1);

        Parser_init("ptlctl > ", list);
        if (argc > 1)
                return Parser_execarg(argc - 1, &argv[1], list);

        Parser_commands();

        return 0;
}
