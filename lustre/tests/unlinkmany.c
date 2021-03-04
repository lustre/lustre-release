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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
	printf("usage: %s [option] filenamefmt count\n", prog);
	printf("       %s [option] filenamefmt start count\n", prog);
	printf("Options are:\n");
	printf("       -d : remove directory\n");
	printf("Examples:\n");
	printf("unlinkmany $DIR/dir 100 # Remove file dir0..dir99\n");
	printf("unlinkmany -d $DIR/dir 100 # Remove directory dir0..dir99\n");
}

int main(int argc, char **argv)
{
	int i, rc = 0, do_rmdir = 0;
	char format[4096], *fmt;
	char filename[4096];
	long start, last;
	long begin = 0, count;

	if (argc < 3 || argc > 5) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-d") == 0) {
		do_rmdir = 1;
		argv++;
		argc--;
	}

	if (strlen(argv[1]) > 4080) {
		printf("name too long\n");
		return 1;
	}

	start = time(0);
	last = start;

	if (argc == 3) {
		count = strtol(argv[2], NULL, 0);
		if (count < 1) {
			printf("count must be at least one\n");
			return 1;
		}
	} else {
		begin = strtol(argv[2], NULL, 0);
		count = strtol(argv[3], NULL, 0);
	}

	if (strchr(argv[1], '%')) {
		fmt = argv[1];
	} else {
		sprintf(format, "%s%%d", argv[1]);
		fmt = format;
	}

	for (i = 0; i < count; i++, begin++) {
		sprintf(filename, fmt, begin);
		if (do_rmdir)
			rc = rmdir(filename);
		else
			rc = unlink(filename);
		if (rc) {
			printf("%s(%s) error: %s\n",
			       do_rmdir ? "rmdir" : "unlink",
			       filename, strerror(errno));
			rc = errno;
			break;
		}
		if ((i % 10000) == 0) {
			printf(" - unlinked %d (time %ld ; total %ld ; last %ld)\n",
			       i, time(0), time(0) - start, time(0) - last);
			last = time(0);
		}
	}
	printf("total: %d unlinks in %ld seconds: %f unlinks/second\n", i,
	       time(0) - start, ((float)i / (time(0) - start)));

	return rc;
}
