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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

void usage(char *prog)
{
	printf("usage: %s [-s] [-b <bytes>] filename\n", prog);
	exit(1);
}

int main(int argc, char **argv)
{
	bool limit_write = false, do_sync = false;
	int c, per_write, fd, rc;
	unsigned long bytes = 0;
	char buf[4096];
	char *endptr = NULL;

	while ((c = getopt(argc, argv, "sb:")) != -1) {
		switch (c) {
		case 's':
			do_sync = true;
			break;
		case 'b':
			limit_write = true;
			bytes = strtoul(optarg, &endptr, 10);
			if (endptr != NULL && *endptr != '\0')
				usage(argv[0]);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (argc - optind != 1)
		usage(argv[0]);

	memset(buf, 0, 4096);
	fd = open(argv[optind], O_RDWR | O_CREAT, 0600);
	if (fd == -1) {
		printf("Error opening %s\n", argv[1]);
		exit(1);
	}

	/* Even 0 bytes, write at least once */
	if (limit_write) {
		do {
			per_write = bytes > 4096 ? 4096 : bytes;
			rc = write(fd, buf, per_write);
			if (rc > 0)
				bytes -= rc;
			else if (rc < 0)
				break;
		} while (bytes > 0);

		return rc >= 0 ? 0 : rc;
	}

	for (rc = 0; ;) {
		sprintf(buf, "write %d\n", rc);
		rc = write(fd, buf, sizeof(buf));
		if (do_sync)
			sync();
		sleep(1);
	}

	return 0;
}
