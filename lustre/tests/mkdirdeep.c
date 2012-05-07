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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/tests/mkdirdeep.c
 *
 * Compile with:
 * cc -I../../lnet/include -o mkdirdeep mkdirdeep.c
 *    -L../../lnet/linux/utils -lptlctl
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <libcfs/lltrace.h>

static int opt_verbose = 0;
static int opt_trace = 0;

void usage(const char *pname)
{
        fprintf(stderr, "Usage: %s --depth <d> [--output <outputtracefilename>]"
                " [--mknod] [--verbose] [--notrace] <basepath>\n", pname);
        exit(1);
}

int do_mkdir(char *path)
{
        int rc = mkdir(path, 0755);

        if (rc) {
                fprintf(stderr, "mkdir(%s) failed: %s\n",
                        path, strerror(errno));
                exit(1);
        }
        if (opt_verbose)
                printf("mkdir %s\n", path);

        return rc;
}


int do_mknod(char *path)
{
        int rc = mknod(path, 0755, S_IFIFO);

        if (rc) {
                fprintf(stderr, "mkdir(%s) failed: %s\n",
                        path, strerror(errno));
                exit(1);
        }
        if (opt_verbose)
                printf("mknod %s\n", path);

        return rc;
}

int do_chdir(char* path)
{
        int rc = chdir(path);

        if (rc) {
                fprintf(stderr, "chdir(%s) failed: %s\n",
                        path, strerror(errno));
                exit(1);
        }
        if (opt_verbose)
                printf("chdir %s\n", path);

        return rc;
}

int do_stat(char *path)
{
        char mark_buf[PATH_MAX + 50];
        struct stat mystat;
        int rc = stat(path, &mystat);

        if (rc) {
                fprintf(stderr, "stat(%s) failed: %s\n",
                        path, strerror(errno));
                exit(1);
        }
        if (opt_verbose)
                printf("stat %s = inode %lu\n", path,
                       (unsigned long)mystat.st_ino);

        if (opt_trace) {
                snprintf(mark_buf, PATH_MAX, "stat %s = inode %lu",
                         path, (unsigned long)mystat.st_ino);
                ltrace_mark(0, mark_buf);
        }

        return rc;
}

int main(int argc, char** argv)
{
        int c, i, mypid;
        int opt_depth = 1;
        int opt_mknod = 0;

        static struct option long_opt[] = {
                {"depth", 1, 0, 'd' },
                {"help", 0, 0, 'h' },
                {"mknod", 0, 0, 'm' },
                {"output", 1, 0, 'o' },
                {"trace", 1, 0, 't' },
                {"verbose", 0, 0, 'v' },
                {0,0,0,0}
        };

        char *outputfilename = NULL;
        char *base_pathname;
        char pathname[PATH_MAX];
        char mark_buf[PATH_MAX + 50];
        char mycwd[PATH_MAX];
        char *pname = argv[0];

        while ((c = getopt_long(argc, argv, "d:mhvo:", long_opt, NULL)) != -1) {
                switch (c) {
                case 'd':
                        opt_depth = atoi(optarg);
                        if ((opt_depth == 0) || (opt_depth > 1100))
                                usage(pname);
                        break;
                case 'm':
                        opt_mknod = 1;
                        break;
                case 't':
                        opt_trace = 1;
                        break;
                case 'v':
                        opt_verbose = 1;
                        break;
                case 'o':
                        outputfilename = optarg;
                        break;
                case 'h':
                case '?':
                case ':':
                default:
                        usage(pname);
                        break;
                }
        }

        if (optind != (argc - 1))
                usage(pname);

        base_pathname = argv[optind];
        mypid = getpid();

        if (!getcwd(&mycwd[0], sizeof(mycwd))) {
                fprintf(stderr, "%s: unable to getcwd()\n", pname);
                exit(1);
        }

        printf("%s(pid=%d) depth=%d mknod=%d, basepathname=%s, trace=%d\n",
               pname, mypid, opt_depth, opt_mknod, base_pathname, opt_trace);

        if (outputfilename)
                printf("outputfilename=%s\n", outputfilename);

        if (opt_trace) {
                ltrace_start();
                ltrace_clear();
                snprintf(mark_buf, PATH_MAX, "Initialize - mkdir %s; chdir %s",
                         base_pathname, base_pathname);
                ltrace_mark(2, mark_buf);
        }

        if (do_mkdir(base_pathname)!=0)
                exit(1);
        if (do_chdir(base_pathname)!=0)
                exit(1);

        /* Create directory tree with depth level of subdirectories */

        if (opt_trace) {
                snprintf(mark_buf, PATH_MAX,
                         "Create Directory Tree (depth %d)", opt_depth);
                ltrace_mark(2, mark_buf);
        }

        for (i = 0; i < opt_depth; i++) {
                snprintf(pathname, sizeof(pathname), "%d", i + 1);

                if (i == (opt_depth - 1)) {
                        /* Last Iteration */

                        if (opt_trace) {
                                snprintf(mark_buf, PATH_MAX,
                                         "Tree Leaf (%d) %s/stat", i,
                                         (opt_mknod ? "mknod" : "mkdir"));
                                ltrace_mark(3, mark_buf);
                        }

                        if (opt_mknod)
                                do_mknod(pathname);
                        else
                                do_mkdir(pathname);
                        /* Now stat it */
                        do_stat(pathname);
                } else {
                        /* Not Leaf */

                        if (opt_trace) {
                                snprintf(mark_buf, sizeof(mark_buf),
                                         "Tree Level (%d) mkdir/stat/chdir", i);
                                ltrace_mark(3, mark_buf);
                        }

                        do_mkdir(pathname);
                        do_stat(pathname);
                        do_chdir(pathname);
                }
        }

        /* Stat through directory tree with fullpaths */

        if (opt_trace) {
                snprintf(mark_buf, PATH_MAX, "Walk Directory Tree");
                ltrace_mark(2, mark_buf);
        }

        do_chdir(base_pathname);

        strncpy(pathname, base_pathname, sizeof(pathname));

        c = strlen(base_pathname);
        for (i = 0; i < opt_depth; i++) {
                c += snprintf(pathname + c, sizeof(pathname) - c, "/%d", i+1);

                if (opt_trace) {
                        snprintf(mark_buf, PATH_MAX, "stat %s", pathname);
                        ltrace_mark(2, mark_buf);
                }

                do_stat(pathname);
        }

        if (opt_trace && outputfilename) {
                    ltrace_write_file(outputfilename);
                    ltrace_add_processnames(outputfilename);
                    ltrace_stop();
        }

        do_chdir(base_pathname);

        printf("%s (pid=%d) done.\n", pname, mypid);

        return 0;
}
