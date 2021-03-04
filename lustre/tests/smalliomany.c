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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

static void usage(char *prog)
{
	printf("usage: %s {-w|-a|-r} filenamefmt count seconds\n"
	       "-w : write mode\n"
	       "-a : append\n"
	       "-r : read mode\n", prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	int do_read = 0, do_append = 0;
	char *base, *endp;
	long int start, last;
	long end = ~0UL >> 1, count = ~0UL >> 1;
	int c, i, fd, rc = 0, len, mode = 0;
	long nbytes = 0;
	char buf[4096];

	while ((c = getopt(argc, argv, "war")) != -1) {
		switch (c) {
		case 'w':
			mode = O_RDWR;
			break;
		case 'a':
			do_append = 1;
			mode = O_RDWR | O_APPEND;
			break;
		case 'r':
			do_read = 1;
			mode = O_RDONLY;
			break;
		case '?':
			printf("Unknown option '%c'\n", optopt);
			usage(argv[0]);
		}
	}

	if (optind + 3 != argc) {
		fprintf(stderr,
			"missing filenamebase, total_files, or seconds\n");
		usage(argv[0]);
	}

	base = argv[optind];
	if (strlen(base) > 4080) {
		fprintf(stderr, "filenamebase too long\n");
		exit(1);
	}

	count = strtoul(argv[optind + 1], NULL, 0);

	end = strtoul(argv[optind + 2], &endp, 0);
	if (end <= 0 && *endp != '\0') {
		fprintf(stderr, "%s: error: bad number of seconds '%s'\n",
			argv[0], argv[optind + 2]);
		exit(2);
	}

	srand(42);

	start = last = time(0);
	end += start;

	for (i = 0; i < count && time(0) < end; i++) {
		char filename[4096];

		snprintf(filename, sizeof(filename), "%s%d", base, i);

		fd = open(filename, mode, 0666);
		if (fd < 0) {
			fprintf(stderr, "fail to open %s\n", filename);
			rc = errno;
			break;
		}

		len = random() % 4096;

		if (do_read == 0) {
			c = write(fd, buf, len);
			if (c != len) {
				fprintf(stderr, "fail to write %s, len %d,"
					" written %d\n", filename, len, c);
				rc = errno;
				break;
			}
		} else {
			c = read(fd, buf, len);
		}
		nbytes += c;

		if (close(fd) < 0) {
			fprintf(stderr, "can't close %s\n", filename);
			rc = errno;
			break;
		}

		if (i && (i % 10000) == 0) {
			printf(" - %ld bytes (time %ld total %ld last %ld)"
			       "\n", nbytes, time(0), time(0) - start,
			       time(0) - last);
			last = time(0);
		}
	}
	printf("total: %s %ld bytes in %ld seconds: %.2f bytes/second\n",
	       do_read ? "read" : do_append ? "append" : "write", nbytes,
	       time(0) - start, ((double)nbytes / (time(0) - start)));

	return rc;
}
