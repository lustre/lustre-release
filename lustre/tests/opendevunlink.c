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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	char *dname1, *dname2;
	int fddev1, fddev2, rc;
	struct stat st1, st2;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: %s filename1 [filename2]\n", argv[0]);
		exit(1);
	}

	dname1 = argv[1];
	if (argc == 3)
		dname2 = argv[2];
	else
		dname2 = argv[1];

	/* create the special file (right now only test on pipe) */
	fprintf(stderr, "creating special file %s\n", dname1);
	rc = mknod(dname1, 0777 | S_IFIFO, 0);
	if (rc == -1) {
		fprintf(stderr, "creating %s fails: %s\n",
			dname1, strerror(errno));
		exit(1);
	}

	/* open the special file again */
	fprintf(stderr, "opening file\n");
	fddev1 = open(dname1, O_RDONLY | O_NONBLOCK);
	if (fddev1 == -1) {
		fprintf(stderr, "open %s fails: %s\n",
			dname1, strerror(errno));
		exit(1);
	}

	/* doesn't matter if the two dirs are the same?? */
	fddev2 = open(dname2, O_RDONLY | O_NONBLOCK);
	if (fddev2 == -1) {
		fprintf(stderr, "open %s fails: %s\n",
			dname2, strerror(errno));
		exit(1);
	}

	/* delete the special file */
	fprintf(stderr, "unlinking %s\n", dname1);
	rc = unlink(dname1);
	if (rc) {
		fprintf(stderr, "unlink %s error: %s\n",
			dname1, strerror(errno));
		exit(1);
	}

	if (access(dname2, F_OK) == 0) {
		fprintf(stderr, "%s still exists\n", dname2);
		exit(1);
	}

	if (access(dname1, F_OK) == 0) {
		fprintf(stderr, "%s still exists\n", dname1);
		exit(1);
	}

	/* fchmod one special file */
	rc = fchmod(fddev1, 0777);
	if (rc == -1) {
		fprintf(stderr, "fchmod unlinked special file %s fails: %s\n",
			dname1, strerror(errno));
		exit(1);
	}

	/* fstat two files to check if they are the same */
	rc = fstat(fddev1, &st1);
	if (rc == -1) {
		fprintf(stderr, "fstat unlinked special file %s fails: %s\n",
			dname1, strerror(errno));
		exit(1);
	}

	rc = fstat(fddev2, &st2);
	if (rc == -1) {
		fprintf(stderr, "fstat file %s fails: %s\n",
			dname2, strerror(errno));
		exit(1);
	}

	fprintf(stderr, "Ok, everything goes well.\n");
	return 0;
}
