/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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

#include <linux/unistd.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef __NR_newpag
#define __NR_newpag		289
#define __NR_getpag		290
#endif

_syscall0(int, newpag);
_syscall0(int, getpag);

void usage(const char *exe)
{
	printf("Usage: %s -k \"parameters_to_kinit\" command line\n", exe);
	exit(1);
}

int check_kopt(const char *opt)
{
        /* FIXME check "-c" here */
        return 0;
}

#define CMD_BUFSIZE	4096

int main(int argc, char *argv[])
{
        extern char *optarg;
        int opt, i;
	unsigned long pag;
        char kopt[CMD_BUFSIZE];
        char kcmd[CMD_BUFSIZE];
	char cmd[CMD_BUFSIZE];

        kopt[0] = '\0';
        cmd[0] = '\0';

        if (getuid() == 0) {
                fprintf(stderr, "root user don't want to use lkinit\n");
                return 1;
        }

	newpag();
	pag = getpag();

        snprintf(kcmd, CMD_BUFSIZE, "kinit -c /tmp/krb5cc_pag_%lx", pag);

        while ((opt = getopt(argc, argv, "k:")) != -1) {
                switch (opt) {
                case 'k':
                        if (check_kopt(optarg)) {
                                fprintf(stderr, "Can't specify cache file\n");
                                return 1;
                        }

                        snprintf(kcmd, CMD_BUFSIZE,
                                 "kinit -c /tmp/krb5cc_pag_%lx %s",
                                 pag, optarg);
                        break;
                default:
                        usage(argv[0]);
                }
        }

	if (optind >= argc) {
		snprintf(cmd, CMD_BUFSIZE, "/bin/sh");
	} else {
                for (i = optind; i < argc; i++) {
                        if (i != optind)
                                strncat(cmd, " ", CMD_BUFSIZE);
                        strncat(cmd, argv[i], CMD_BUFSIZE);
                }
	}

        if (system(kcmd)) {
                fprintf(stderr, "can't get kerberos TGT\n");
                return 1;
        }

        if (system(cmd))
                fprintf(stderr, "execute error\n");

        /* flush in-kernel credential cache */
        snprintf(cmd, CMD_BUFSIZE, "lfs flushctx");
        if (system(cmd))
                fprintf(stderr, "failed to flush in-kernel credential\n");

        /* flush user-space credential cache */
        snprintf(kcmd, CMD_BUFSIZE, "kdestroy -c /tmp/krb5cc_pag_%lx", pag);
        system(kcmd);

	return 0;
}
