/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Robert Read <rread@clusterfs.com> 
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#define printk printf


#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <asm/page.h>   /* needed for PAGE_SIZE - rread*/ 

#include "lctl.h"

#define __KERNEL__
#include <linux/list.h>
#undef __KERNEL__

int thread;

command_t cmdlist[];

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
        {"network", jt_net_network, 0, "commands that follow apply to net\n"
         "usage: network <tcp/elan/myrinet>"},       
        {"connect", jt_net_connect, 0, "connect to a remote nid\n"
         "usage: connect [[<hostname> <port>] | <elan id>]"},
        {"disconnect", jt_net_disconnect, 0, "disconnect from a remote nid\n"
         "usage: disconnect <nid>"},
        {"mynid", jt_net_mynid, 0, "inform the socknal of the local nid. "
         "The nid defaults to hostname for tcp networks and is automatically "
         "setup for elan/myrinet networks.\n"
         "usage: mynid [nid]"},
        {"add_uuid", jt_net_add_uuid, 0, "associate a name/uuid with a nid\n"
         "usage: add_uuid <name> <uuid> <nid>"},
        {"del_uuid", jt_net_del_uuid, 0, "delete a uuid association\n"
         "usage: del_uuid <uuid>"},
        {"add_route", jt_net_add_route, 0,
         "add an entry to the routing table\n"
         "usage: add_route <gateway> <target> [target]"},
        {"del_route", jt_net_del_route, 0,
         "delete an entry from the routing table\n"
         "usage: del_route <target>"},
        {"route_list", jt_net_route_list, 0, "print the routing table\n"
         "usage: route_list"},
        {"recv_mem", jt_net_recv_mem, 0, "set socket receive buffer size, "
         "if size is omited the current size is reported.\n"
         "usage: recv_mem [size]"},
        {"send_mem", jt_net_send_mem, 0, "set socket send buffer size, "
         "if size is omited the current size is reported.\n"
         "usage: send_mem [size]"},
        {"nagle", jt_net_nagle, 0, "enable/disable nagle, omiting the "
         "argument will cause the current nagle setting to be reported.\n" 
         "usage: nagle [on/off]"},       
                
        /* Device selection commands */
        {"=== device selection ===", jt_noop, 0, "device selection"},
        {"newdev", jt_dev_newdev, 0, "create a new device\n"
         "usage: newdev"},
        {"uuid2dev", jt_dev_uuid2dev, 0,
         "find a uuid and make it the current device\n"
         "usage: uuid2dev <uuid>"},
        {"name2dev", jt_dev_name2dev, 0,
         "find a name and make it the current device\n"
         "usage: name2dev <name>"},
        {"device", jt_dev_device, 0, "set current device to devno\n"
         "usage: device <devno>"},
        {"device_list", jt_dev_list, 0, "show all devices\n"
         "usage: device_list"},
         
        /* Device configuration commands */
        {"==== device config =====", jt_noop, 0, "device config"},
        {"attach", jt_dev_attach, 0, "name and type the device\n"
         "usage: attach type [name [uuid]]"},
        {"setup", jt_dev_setup, 0,
         "type specific device configuration information\n"
         "usage: setup <args...>"},
        {"cleanup", jt_dev_cleanup, 0, "cleanup setup\n"
         "usage: cleanup"},
        {"detach", jt_dev_detach, 0, "un-name a device\n"
         "usage: detach"},
        {"lovconfig", jt_dev_lov_config, 0,
         "write lov configuration to a mds device\n"
         "usage: lovconfig"},

        /* Device operations */
        {"=== device operations ==", jt_noop, 0, "device operations"},
        {"probe", jt_dev_probe, 0,
         "build a connection handle to a device.  This command is used too "
         "suspend configuration until lctl has ensured that the mds and osc "
         "services are available.  This is to avoid mount failures in a "
         "rebooting cluster.\n"
         "usage: probe [<timeout]"},
        {"close", jt_dev_close, 0, "close the connection handle\n"
         "usage: close"},
        {"getattr", jt_dev_getattr, 0, "get attribute for id\n"
         "usage: getattr <id>"},
        {"setattr", jt_dev_setattr, 0, "set attribute for id\n"
         "usage: setattr <id> <mode>"},
        {"test_getattr", jt_dev_test_getattr, 0,
         "perform count number of getattr's\n"
         "usage: test_getattr <count> [verbose]"},
        {"test_brw", jt_dev_test_brw, 0,
         "perform count number of bulk read/writes\n"
         "usage: test_brw <count> [write [verbose [pages [obdos]]]]"},
        {"test_ldlm", jt_dev_test_ldlm, 0, "perform lock manager test\n"
         "usage: test_ldlm"},

#if 0
        {"create", jt_create, 0, "create [count [mode [verbose]]]"},
        {"destroy", jt_destroy, 0, "destroy <id>"},
        {"newconn", jt_newconn, 0, "newconn [newuuid]"},
#endif
        /* Debug commands */
        {"======== debug =========", jt_noop, 0, "debug"},
        {"debug_lctl", jt_debug_lctl, 0,
         "set debug status of lctl "
         "usage: debug_kernel [file] [raw]"},
        {"debug_kernel", jt_debug_kernel, 0,
         "get debug buffer and dump to a file"
         "usage: debug_kernel [file] [raw]"},
        {"debug_file", jt_debug_file, 0,
         "read debug buffer from input and dump to output"
         "usage: debug_file <input> [output] [raw]"},
        {"clear", jt_debug_clear, 0, "clear kernel debug buffer\n"
         "usage: clear"},
        {"mark", jt_debug_mark, 0,"insert marker text in kernel debug buffer\n"
         "usage: mark <text>"},
        {"filter", jt_debug_filter, 0, "filter message type\n"
         "usage: filter <subsystem id/debug mask>"},
        {"show", jt_debug_show, 0, "show message type\n"
         "usage: show <subsystem id/debug mask>"},
        {"debug_list", jt_debug_list, 0, "list subsystem and debug types\n"
         "usage: debug_list <subs/types>"},
        {"modules", jt_debug_modules, 0,
         "provide gdb-friendly module information\n"
         "usage: modules <path>"},
        {"panic", jt_debug_panic, 0, "force the kernel to panic\n"
         "usage: panic"},
         
        /* User interface commands */
        {"======= control ========", jt_noop, 0, "control commands"},
        {"help", Parser_help, 0, "help"},
        {"exit", jt_quit, 0, "quit"},
        {"quit", jt_quit, 0, "quit"},
        { 0, 0, 0, NULL }
};

static void signal_server(int sig) {
        if (sig == SIGINT) {
                do_disconnect("sigint", 1);
                exit(1);
        } else {
                fprintf(stderr, "%s: got signal %d\n", cmdname("sigint"), sig);
        }
}

int get_verbose(const char *arg)
{
        int verbose;

        if (!arg || arg[0] == 'v')
                verbose = 1;
        else if (arg[0] == 's' || arg[0] == 'q')
                verbose = 0;
        else
                verbose = (int) strtoul(arg, NULL, 0);

        if (verbose < 0)
                printf("Print status every %d seconds\n", -verbose);
        else if (verbose == 1)
                printf("Print status every operation\n");
        else if (verbose > 1)
                printf("Print status every %d operations\n", verbose);

        return verbose;
}

int be_verbose(int verbose, struct timeval *next_time,
                      int num, int *next_num, int num_total)
{
        struct timeval now;

        if (!verbose)
                return 0;

        if (next_time != NULL)
                gettimeofday(&now, NULL);

        /* A positive verbosity means to print every X iterations */
        if (verbose > 0 &&
            (next_num == NULL || num >= *next_num || num >= num_total)) {
                *next_num += verbose;
                if (next_time) {
                        next_time->tv_sec = now.tv_sec - verbose;
                        next_time->tv_usec = now.tv_usec;
                }
                return 1;
        }

        /* A negative verbosity means to print at most each X seconds */
        if (verbose < 0 && next_time != NULL && difftime(&now, next_time) >= 0){
                next_time->tv_sec = now.tv_sec - verbose;
                next_time->tv_usec = now.tv_usec;
                if (next_num)
                        *next_num = num;
                return 1;
        }

        return 0;
}

int jt_opt_threads(int argc, char **argv)
{
        int threads, next_thread;
        int verbose;
        int i, j;
        int rc;

        if (argc < 5) {
                fprintf(stderr,
                        "usage: %s numthreads verbose devno <cmd [args ...]>\n",
                        argv[0]);
                return -1;
        }

        threads = strtoul(argv[1], NULL, 0);

        verbose = get_verbose(argv[2]);

        printf("%s: starting %d threads on device %s running %s\n",
               argv[0], threads, argv[3], argv[4]);

        for (i = 1, next_thread = verbose; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%d - %s\n", argv[0], i,
                                strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        thread = i;
                        argv[2] = "--device";
                        return jt_opt_device(argc - 2, argv + 2);
                } else if (be_verbose(verbose, NULL, i, &next_thread, threads))
                        printf("%s: thread #%d (PID %d) started\n",
                               argv[0], i, rc);
                rc = 0;
        }

        if (!thread) { /* parent process */
                if (!verbose)
                        printf("%s: started %d threads\n\n", argv[0], i - 1);
                else
                        printf("\n");

                for (j = 1; j < i; j++) {
                        int status;
                        int ret = wait(&status);

                        if (ret < 0) {
                                fprintf(stderr, "error: %s: wait - %s\n",
                                        argv[0], strerror(errno));
                                if (!rc)
                                        rc = errno;
                        } else {
                                /*
                                 * This is a hack.  We _should_ be able to use
                                 * WIFEXITED(status) to see if there was an
                                 * error, but it appears to be broken and it
                                 * always returns 1 (OK).  See wait(2).
                                 */
                                int err = WEXITSTATUS(status);
                                if (err)
                                        fprintf(stderr,
                                                "%s: PID %d had rc=%d\n",
                                                argv[0], ret, err);
                                if (!rc)
                                        rc = err;
                        }
                }
        }

        return rc;
}

char *cmdname(char *func)
{
	static char buf[512];
	
	if (thread) {
		sprintf(buf, "%s-%d", func, thread);
		return buf;
	}

	return func;
}

int main(int argc, char **argv) {
        struct sigaction sigact;
        int rc;

        sigact.sa_handler = signal_server;
        sigfillset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;
        sigaction(SIGINT, &sigact, NULL);

        if (network_setup(argc, argv) < 0)
                exit(1);
        
        if (device_setup(argc, argv) < 0)
                exit(2);

        if (debug_setup(argc, argv) < 0)
                exit(3);
        
        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                Parser_init("lctl > ", cmdlist);
                rc = Parser_commands();
        }

        do_disconnect(argv[0], 1);
        return rc;
}

