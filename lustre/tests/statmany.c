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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include <lustre/lustreapi.h>

struct option longopts[] = {
	{ .name = "lookup", .has_arg = no_argument, .val = 'l' },
	{ .name = "random", .has_arg = no_argument, .val = 'r' },
	{ .name = "stat", .has_arg = no_argument, .val = 's' },
	{ .name = NULL }
};
char *shortopts = "hlr:s0123456789";

static int usage(char *prog, FILE *out)
{
        fprintf(out,
		"Usage: %s [-r rand_seed] {-s|-l} filenamebase total_files iterations\n"
               "-r : random seed\n"
               "-s : regular stat() calls\n"
               "-l : lookup ioctl only\n", prog);
        exit(out == stderr);
}

#ifndef LONG_MAX
#define LONG_MAX (1 << ((8 * sizeof(long)) - 1))
#endif

int main(int argc, char ** argv)
{
        long i, count, iter = LONG_MAX, mode = 0, offset;
        long int start, length = LONG_MAX, last;
        char parent[4096], *t;
	char *prog = argv[0], *base;
	int seed = 0, rc;
	int fd = -1;

	while ((rc = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		char *e;
		switch (rc) {
		case 'r':
			seed = strtoul(optarg, &e, 0);
			if (*e) {
				fprintf(stderr, "bad -r option %s\n", optarg);
				usage(prog, stderr);
			}
			break;
		case 'l':
		case 's':
			mode = rc;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			if (length == LONG_MAX)
				length = rc - '0';
			else
				length = length * 10 + (rc - '0');
			break;
		case 'h':
			usage(prog, stdout);
		case '?':
			usage(prog, stderr);
		}
	}

	if (optind + 2 + (length == LONG_MAX) != argc) {
		fprintf(stderr, "missing filenamebase, total_files, or iterations\n");
		usage(prog, stderr);
	}

        base = argv[optind];
        if (strlen(base) > 4080) {
                fprintf(stderr, "filenamebase too long\n");
                exit(1);
        }

	if (seed == 0) {
		int f = open("/dev/urandom", O_RDONLY);

		if (f < 0 || read(f, &seed, sizeof(seed)) < sizeof(seed))
			seed = time(0);
		if (f > 0)
			close(f);
	}

	printf("using seed %u\n", seed);
	srand(seed);

        count = strtoul(argv[optind + 1], NULL, 0);
	if (length == LONG_MAX) {
		iter = strtoul(argv[optind + 2], NULL, 0);
		printf("running for %lu iterations\n", iter);
	} else
		printf("running for %lu seconds\n", length);

        start = last = time(0);

        t = strrchr(base, '/');
        if (t == NULL) {
                strcpy(parent, ".");
                offset = -1;
        } else {
                strncpy(parent, base, t - base);
                offset = t - base + 1;
        }

	if (mode == 'l') {
		fd = open(parent, O_RDONLY);
		if (fd < 0) {
			printf("open(%s) error: %s\n", parent,
			       strerror(errno));
			exit(errno);
		}
	}

        for (i = 0; i < iter && time(0) - start < length; i++) {
                char filename[4096];
                int tmp;

                tmp = random() % count;
                sprintf(filename, "%s%d", base, tmp);

		if (mode == 's') {
                        struct stat buf;

                        rc = stat(filename, &buf);
                        if (rc < 0) {
                                printf("stat(%s) error: %s\n", filename,
                                       strerror(errno));
                                break;
                        }
		} else if (mode == 'l') {
			char *name = filename;

			if (offset >= 0)
				name += offset;

			rc = llapi_file_lookup(fd, name);
                        if (rc < 0) {
				printf("llapi_file_lookup for (%s) error: %s\n",
				       filename, strerror(errno));
                                break;
                        }
                }
                if ((i % 10000) == 0) {
                        printf(" - stat %lu (time %ld ; total %ld ; last %ld)\n",
                               i, time(0), time(0) - start, time(0) - last);
                        last = time(0);
                }
        }

	if (mode == 'l')
		close(fd);

        printf("total: %lu stats in %ld seconds: %f stats/second\n", i,
               time(0) - start, ((float)i / (time(0) - start)));

        exit(rc);
}
