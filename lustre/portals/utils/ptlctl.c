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
#include <portals/api-support.h>
#include <portals/ptlctl.h>

#include "parser.h"


command_t list[] = {
        {"network", jt_ptl_network, 0,"setup the NAL (args: nal name)"},
        {"connect", jt_ptl_connect, 0, "connect to a remote nid (args: <hostname port> | <id> for tcp/elan respectively)"},
        {"disconnect", jt_ptl_disconnect, 0, "disconnect from a remote nid (args: [hostname]"},
        {"push", jt_ptl_push_connection, 0, "flush connection to a remote nid (args: [hostname]"},
        {"ping", jt_ptl_ping, 0, "do a ping test (args: nid [count] [size] [timeout])"},
        {"shownid", jt_ptl_shownid, 0, "print the local NID"},
        {"mynid", jt_ptl_mynid, 0, "inform the socknal of the local NID (args: [hostname])"},
        {"add_route", jt_ptl_add_route, 0, "add an entry to the routing table (args: gatewayNID targetNID [targetNID])"},
        {"del_route", jt_ptl_del_route, 0, "delete an entry from the routing table (args: targetNID"},
        {"print_routes", jt_ptl_print_routes, 0, "print the routing table (args: none)"},
        {"recv_mem", jt_ptl_rxmem, 0, "Set socket receive buffer size (args: [size])"},
        {"send_mem", jt_ptl_txmem, 0, "Set socket send buffer size (args: [size])"},
        {"nagle", jt_ptl_nagle, 0, "Enable/Disable Nagle (args: [on/off])"},
        {"dump", jt_ioc_dump, 0, "usage: dump file, save ioctl buffer to file"},
        {"fail", jt_ptl_fail_nid, 0, "usage: fail nid|_all_ [count]"},
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
