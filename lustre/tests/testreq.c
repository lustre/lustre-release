/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define _GNU_SOURCE
#include <getopt.h>
#undef _GNU_SOURCE

#include <linux/lustre_mds.h>

static void usage(char *argv0, int status)
{
        printf(
"Usage: %s [OPTION...]\n\
\n\
--getattr <directory>\n\
--setattr <directory>\n\
--readpage <directory>\n\
--open <directory>\n\
--close <directory handle (returned by open)>\n\
--create <new name>\n", argv0);

        exit(status);
}

int main(int argc, char **argv)
{
        int fd = 0;
        int rc = 0;
        int c  = 0;
        long cmd = 0;
        unsigned long arg;
        char *short_opts = "h", *name = argv[0];
        static struct option long_opts[] = {
#define OPT_GETATTR -2
                {"getattr", no_argument, NULL, OPT_GETATTR},
#define OPT_READPAGE -3
                {"readpage", no_argument, NULL, OPT_READPAGE},
#define OPT_SETATTR -4
                {"setattr", no_argument, NULL, OPT_SETATTR},
#define OPT_CREATE -5
                {"create", no_argument, NULL, OPT_CREATE},
#define OPT_OPEN -6
                {"open", no_argument, NULL, OPT_OPEN},
#define OPT_CLOSE -7
                {"close", required_argument, NULL, OPT_CLOSE},
#define OPT_HELP 'h'
                {"help", no_argument, NULL, OPT_HELP},
                {0}
        };

        do {
                c = getopt_long(argc, argv, short_opts, long_opts, NULL);

                switch (c) {
                case OPT_HELP:
                        usage(argv[0], 0);
                        break;
                case OPT_GETATTR:
                        cmd = IOC_REQUEST_GETATTR;
                        name = "getattr";
                        arg = 2;
                        break;
                case OPT_SETATTR:
                        cmd = IOC_REQUEST_SETATTR;
                        name = "setattr";
                        arg = 2;
                        break;
                case OPT_READPAGE:
                        cmd = IOC_REQUEST_READPAGE;
                        name = "readpage";
                        arg = 2;
                        break;
                case OPT_CREATE:
                        cmd = IOC_REQUEST_CREATE;
                        name ="create";
                        arg = 2;
                        break;
                case OPT_OPEN:
                        cmd = IOC_REQUEST_OPEN;
                        name = "open";
                        arg = 2;
                        break;
                case OPT_CLOSE:
                        cmd = IOC_REQUEST_CLOSE;
                        name = "close";
                        arg = strtoul(optarg, NULL, 0);
                        break;
                case '?':
                        usage(argv[0], 1);
                }
        } while (c != -1);

        if (cmd == 0)
                usage(argv[0], 1);

        fd = open("/dev/request", O_RDONLY);
        if (fd == -1) {
                fprintf(stderr, "error opening /dev/request: %s\n",
                        strerror(errno));
                exit(1);
        }

        fprintf(stderr, "Executing %s test (arg=%lu)...\n", name, arg);
        if (cmd == IOC_REQUEST_OPEN) {
                rc = ioctl(fd, cmd, &arg);
                printf("%lu\n", arg);
        } else
                rc = ioctl(fd, cmd, arg);
        fprintf(stderr, "result code: %d\n", rc);

        return 0;
}
