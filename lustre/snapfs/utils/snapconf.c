/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *      utils/snapconf.c
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <portals/api-support.h>
#include <portals/ptlctl.h>
#include <portals/list.h>
#include "parser.h"
#include "snapctl.h"

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
        {"--ignore_errors", jt_opt_ignore_errors, 0,
         "ignore errors that occur during script processing\n"
         "--ignore_errors"},
        /* snapshot commands*/
        {"add", snapshot_add, 0, 
          "add [table_no] <snap_name> add snapshot to the device\n"},
        {"list", snapshot_list, 0, "snap_list list snap available device\n"},
        {"dev", snapshot_dev, 0, "open <device> open available snap device\n"},

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

        Parser_init("snapconf > ", cmdlist);
        init_snap_list();
        
        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                rc = Parser_commands();
        }

        return rc;
}

