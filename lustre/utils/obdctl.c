/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#include "obdctl.h"
#include "parser.h"

/* the functions that were in here are now in obd.c */

static int jt_quit(int argc, char **argv)
{
        int rc = 0;
        Parser_quit(argc, argv);

        return rc;
}

command_t cmdlist[] = {
        /* Metacommands */
        {"--device", jt_opt_device, 0, "--device <devno> <command [args ...]>"},
        {"--threads", jt_opt_threads, 0,
         "--threads <threads> <devno> <command [args ...]>"},

        /* Device configuration commands */
        {"lov_setconfig", jt_obd_lov_setconfig, 0, "configure lov data on MDS "
         "[usage: lovconfig lov-uuid stripecount, stripesize, pattern, UUID1, [UUID2, ...]"},
        {"list", jt_obd_list, 0, "list the devices (no args)"},
        {"newdev", jt_obd_newdev, 0, "set device to a new unused obd (no args)"},
        {"device", jt_obd_device, 0, "set current device (args device_no name)"},
        {"name2dev", jt_obd_name2dev, 0,
         "set device by name [usage: name2dev devname]"},
        {"attach", jt_obd_attach, 0, "name the type of device (args: type data"},
        {"setup", jt_obd_setup, 0, "setup device (args: <blkdev> [data]"},
        {"detach", jt_obd_detach, 0, "detach the current device (arg: )"},
        {"cleanup", jt_obd_cleanup, 0, "cleanup the current device (arg: )"},

        /* Session commands */
        {"connect", jt_obd_connect, 0, "connect - get a connection to device"},
        {"disconnect", jt_obd_disconnect, 0,
         "disconnect - break connection to device"},

        /* Session operations */
        {"create", jt_obd_create, 0, "create [count [mode [verbose]]]"},
        {"destroy", jt_obd_destroy, 0, "destroy <id>"},
        {"getattr", jt_obd_getattr, 0, "getattr <id>"},
        {"setattr", jt_obd_setattr, 0, "setattr <id> <mode>"},
        {"newconn", jt_obd_newconn, 0, "newconn <olduuid> [newuuid]"},
        {"test_getattr", jt_obd_test_getattr, 0, "test_getattr <count> [verbose [[t]objid]]"},
        {"test_brw", jt_obd_test_brw, 0, "test_brw [t]<count> [write [verbose [pages [[t]objid]]]]"},
        {"test_ldlm", jt_obd_test_ldlm, 0, "test lock manager (no args)"},
        {"dump_ldlm", jt_obd_dump_ldlm, 0, "dump all lock manager state (no args)"},

        /* User interface commands */
        {"help", Parser_help, 0, "help"},
        {"exit", jt_quit, 0, "quit"},
        {"quit", jt_quit, 0, "quit"},
        {0, 0, 0, NULL}
};


int main(int argc, char **argv)
{
        int rc;

        setlinebuf(stdout);

        if (obd_initialize(argc, argv) < 0)
                exit(1);

        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                Parser_init("obdctl > ", cmdlist);
                rc = Parser_commands();
        }

        obd_cleanup(argc, argv);
        return rc;
}
