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
 * Some day I'll split all of this functionality into a cfs_debug module
 * of its own.  That day is not today.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <lnet/api-support.h>
#include <lnet/lnetctl.h>
#include "parser.h"


command_t list[] = {
        {"debug_kernel", jt_dbg_debug_kernel, 0, "usage: debug_kernel [file] [raw], get debug buffer and print it [to a file]"},
        {"debug_daemon", jt_dbg_debug_daemon, 0, "usage: debug_daemon [start file|stop], control debug daemon to dump debug buffer to a file"}, 
        {"debug_file", jt_dbg_debug_file, 0, "usage: debug_file <input> [output] [raw], read debug buffer from input and print it [to output]"},
        {"clear", jt_dbg_clear_debug_buf, 0, "clear kernel debug buffer"},
        {"mark", jt_dbg_mark_debug_buf, 0, "insert a marker into the kernel debug buffer (args: [marker text])"},
        {"filter", jt_dbg_filter, 0, "filter certain messages (args: subsystem/debug ID)\n"},
        {"show", jt_dbg_show, 0, "enable certain messages (args: subsystem/debug ID)\n"},
        {"list", jt_dbg_list, 0, "list subsystem and debug types (args: subs or types)\n"},
        {"modules", jt_dbg_modules, 0, "provide gdb-friendly module info (arg: <path>)"},
        {"panic", jt_dbg_panic, 0, "cause the kernel to panic"},
        {"dump", jt_ioc_dump, 0, "usage: dump file, save ioctl buffer to file"},
        {"help", Parser_help, 0, "help"},
        {"exit", Parser_quit, 0, "quit"},
        {"quit", Parser_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};

int main(int argc, char **argv)
{
        if (dbg_initialize(argc, argv) < 0)
                exit(2);

        register_ioc_dev(LNET_DEV_ID, LNET_DEV_PATH, 
                         LNET_DEV_MAJOR, LNET_DEV_MINOR);

        Parser_init("debugctl > ", list);
        if (argc > 1)
                return Parser_execarg(argc - 1, &argv[1], list);

        Parser_commands();

        unregister_ioc_dev(LNET_DEV_ID);
        return 0;
}
