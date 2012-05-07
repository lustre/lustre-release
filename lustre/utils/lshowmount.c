/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/lshowmount.h
 *
 * Author: Herb Wartens <wartens2@llnl.gov>
 * Author: Jim Garlick <garlick@llnl.gov>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <libgen.h>

#include "nidlist.h"

#define PROC_DIRS {                     \
        "/proc/fs/lustre/mgs",          \
        "/proc/fs/lustre/mdt",          \
        "/proc/fs/lustre/obdfilter",    \
        NULL,                           \
}
#define PROC_EXPORTS_TMPL       "%s/%s/exports"
#define PROC_UUID_TMPL          "%s/%s/uuid"

static void print_nids(NIDList nidlist, int lookup, int enumerate, int indent);
static int lshowmount(int lookup, int enumerate, int verbose);
static void read_exports(char *exports, NIDList nidlist);

char *prog;

#define OPTIONS "ehlv"
static struct option long_options[] = {
        {"enumerate", no_argument, 0, 'e'},
        {"help",      no_argument, 0, 'h'},
        {"lookup",    no_argument, 0, 'l'},
        {"verbose",   no_argument, 0, 'v'},
        {0, 0, 0, 0},
};

static void usage(void)
{
        fprintf(stderr, "usage: %s [-e] [-h] [-l] [-v]\n", prog);
        exit(1);
}

int main(int argc, char **argv)
{
        int opt, optidx = 0;
        int lopt = 0;
        int vopt = 0;
        int eopt = 0;

        prog = basename(argv[0]);

        while ((opt = getopt_long(argc, argv, OPTIONS, long_options, &optidx)) != -1) {
                switch (opt) {
                        case 'e':       /* --enumerate */
                                eopt = 1;
                                break;
                        case 'l':       /* --lookup */
                                lopt = 1;
                                break;
                        case 'v':       /* --verbose */
                                vopt = 1;
                                break;
                        case 'h':       /* --help */
                        default:
                                usage();
                }
        }

        if (lshowmount(lopt, eopt, vopt) == 0) {
                fprintf(stderr, "%s: lustre server modules not loaded\n", prog);
                exit(1);
        }
        exit(0);
}

static void print_nids(NIDList nidlist, int lookup, int enumerate, int indent)
{
        char *s, *sep = "\n", *pfx = "";

        if (lookup)
                nl_lookup_ip(nidlist);
        nl_sort(nidlist);
        nl_uniq(nidlist);
        if (nl_count(nidlist) > 0) {
                if (indent) {
                        sep = "\n    ";
                        pfx = "    ";
                }
                if (enumerate)
                        s = nl_string(nidlist, sep);
                else
                        s = nl_xstring(nidlist, sep);
                printf("%s%s\n", pfx, s);
                free(s);
        }
}

static int lshowmount(int lookup, int enumerate, int verbose)
{
        char *dirs[] = PROC_DIRS;
        char exp[PATH_MAX + 1];
        NIDList nidlist = NULL;
        DIR *topdirp;
        struct dirent *dp;
        int i;
        int opens = 0;

        if (!verbose)
                nidlist = nl_create();
        for (i = 0; dirs[i] != NULL; i++) {
                if ((topdirp = opendir(dirs[i])) == NULL)
                        continue;
                while ((dp = readdir(topdirp))) {
                        if (dp->d_type != DT_DIR)
                                continue;
                        if (!strcmp(dp->d_name, "."))
                                continue;
                        if (!strcmp(dp->d_name, ".."))
                                continue;
                        sprintf(exp, PROC_EXPORTS_TMPL, dirs[i], dp->d_name);
                        if (verbose) {
                                nidlist = nl_create();
                                read_exports(exp, nidlist);
                                printf("%s:\n", dp->d_name);
                                print_nids(nidlist, lookup, enumerate, 1);
                                nl_destroy(nidlist);
                        } else
                                read_exports(exp, nidlist);
                }
                closedir(topdirp);
                opens++;
        }
        if (!verbose) {
                print_nids(nidlist, lookup, enumerate, 0);
                nl_destroy(nidlist);
        }
        return opens;
}

static int empty_proc_file(char *path)
{
        int empty = 0;
        char buf[36];
        int fd;

        if ((fd = open(path, O_RDONLY)) < 0 || read(fd, buf, sizeof(buf)) <= 0)
                empty = 1;
        if (fd >= 0)
                close(fd);
        return empty;
}

static void read_exports(char *exports, NIDList nidlist)
{
        DIR *dirp;
        struct dirent *dp;
        char path[PATH_MAX + 1];

        if ((dirp = opendir(exports))) {
                while ((dp = readdir(dirp))) {
                        if (dp->d_type != DT_DIR)
                                continue;
                        if (!strcmp(dp->d_name, "."))
                                continue;
                        if (!strcmp(dp->d_name, ".."))
                                continue;
                        if (strchr(dp->d_name, '@') == NULL)
                                continue;
                        sprintf(path, PROC_UUID_TMPL, exports, dp->d_name);
                        if (empty_proc_file(path))
                                continue;

                        nl_add(nidlist, dp->d_name);
                }
                closedir(dirp);
        }
}
