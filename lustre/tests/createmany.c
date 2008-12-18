/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

void usage(char *prog)
{
        printf("usage: %s {-o|-m|-d|-l<tgt>} filenamefmt count\n", prog);
        printf("       %s {-o|-m|-d|-l<tgt>} filenamefmt -seconds\n", prog);
        printf("       %s {-o|-m|-d|-l<tgt>} filenamefmt start count\n", prog);
}

int main(int argc, char ** argv)
{
        int i, rc = 0, do_open = 0, do_link = 0, do_mkdir = 0;
        char format[4096], *fmt, *tgt = NULL;
        char filename[4096];
        long start, last, end;
        long begin = 0, count;

        if (argc < 4 || argc > 5) {
                usage(argv[0]);
                return 1;
        }

        if (strcmp(argv[1], "-d") == 0) {
                do_mkdir = 1;
        } else if (strcmp(argv[1], "-o") == 0) {
                do_open = 1;
        } else if (strncmp(argv[1], "-l", 2) == 0 && argv[1][2]) {
                tgt = argv[1] + 2;
                do_link = 1;
        } else if (strcmp(argv[1], "-m") != 0) {
                usage(argv[0]);
                return 1;
        }

        if (strlen(argv[2]) > 4080) {
                printf("name too long\n");
                return 1;
        }

        start = last = time(0);

        if (argc == 4) {
                end = strtol(argv[3], NULL, 0);
        } else {
                begin = strtol(argv[3], NULL, 0);
                end = strtol(argv[4], NULL, 0);
        }

        if (end > 0) {
                count = end;
                end = -1UL >> 1;
        } else {
                end = start - end;
                count = -1UL >> 1;
        }

        if (strchr(argv[2], '%'))
                fmt = argv[2];
        else {
                sprintf(format, "%s%%d", argv[2]);
                fmt = format;
        }
        for (i = 0; i < count && time(0) < end; i++, begin++) {
                sprintf(filename, fmt, begin);
                if (do_open) {
                        int fd = open(filename, O_CREAT|O_RDWR, 0644);
                        if (fd < 0) {
                                printf("open(%s) error: %s\n", filename,
                                       strerror(errno));
                                rc = errno;
                                break;
                        }
                        close(fd);
                } else if (do_link) {
                        rc = link(tgt, filename);
                        if (rc) {
                                printf("link(%s, %s) error: %s\n",
                                       tgt, filename, strerror(errno));
                                rc = errno;
                                break;
                        }
                } else if (do_mkdir) {
                        rc = mkdir(filename, 0755);
                        if (rc) {
                                printf("mkdir(%s) error: %s\n",
                                       filename, strerror(errno));
                                rc = errno;
                                break;
                        }
                } else {
                        rc = mknod(filename, S_IFREG| 0444, 0);
                        if (rc) {
                                printf("mknod(%s) error: %s\n",
                                       filename, strerror(errno));
                                rc = errno;
                                break;
                        }
                }
                if ((i % 10000) == 0) {
                        printf(" - created %d (time %ld total %ld last %ld)\n",
                               i, time(0), time(0) - start, time(0) - last);
                        last = time(0);
                }
        }
        printf("total: %d creates in %ld seconds: %f creates/second\n", i,
               time(0) - start, ((float)i / (time(0) - start)));

        return rc;
}
