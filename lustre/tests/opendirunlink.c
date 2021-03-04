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

/* for O_DIRECTORY */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

int main(int argc, char **argv)
{
	char *dname1, *dname2;
	int fddir1, fddir2, rc;
	struct stat st1, st2;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: %s dirname1 [dirname2]\n", argv[0]);
		exit(1);
	}

	dname1 = argv[1];
	if (argc == 3)
		dname2 = argv[2];
	else
		dname2 = argv[1];

	/* create the directory */
	fprintf(stderr, "creating directory %s\n", dname1);
	rc = mkdir(dname1, 0744);
	if (rc == -1) {
		fprintf(stderr, "creating %s fails: %s\n",
			dname1, strerror(errno));
		exit(1);
	}

	/* open the dir again */
	fprintf(stderr, "opening directory\n");
	fddir1 = open(dname1, O_RDONLY | O_DIRECTORY);
	if (fddir1 == -1) {
		fprintf(stderr, "open %s fails: %s\n",
			dname1, strerror(errno));
		exit(2);
	}

	/* doesn't matter if the two dirs are the same?? */
	fddir2 = open(dname2, O_RDONLY | O_DIRECTORY);
	if (fddir2 == -1) {
		fprintf(stderr, "open %s fails: %s\n",
			dname2, strerror(errno));
		exit(3);
	}

	/* delete the dir */
	fprintf(stderr, "unlinking %s\n", dname1);
	rc = rmdir(dname1);
	if (rc) {
		fprintf(stderr, "unlink %s error: %s\n",
			dname1, strerror(errno));
		exit(4);
	}

	if (access(dname2, F_OK) == 0) {
		fprintf(stderr, "%s still exists\n", dname2);
		exit(5);
	}

	if (access(dname1, F_OK) == 0) {
		fprintf(stderr, "%s still exists\n", dname1);
		exit(6);
	}

	/* fchmod the dir */
	rc = fchmod(fddir1, 0777);
	if (rc == -1) {
		fprintf(stderr, "fchmod unlinked dir fails %s\n",
			strerror(errno));
		exit(7);
	}

	/* fstat two dirs to check if they are the same */
	rc = fstat(fddir1, &st1);
	if (rc == -1) {
		fprintf(stderr, "fstat unlinked dir %s fails %s\n",
			dname1, strerror(errno));
		exit(8);
	}

	rc = fstat(fddir2, &st2);
	if (rc == -1) {
		fprintf(stderr, "fstat dir %s fails %s\n",
			dname2, strerror(errno));
		exit(9);
	}

	if (st1.st_mode != st2.st_mode) {  /* can we do this? */
		fprintf(stderr, "fstat different value on %s and %s\n",
			dname1, dname2);
		exit(10);
	}

	fprintf(stderr, "Ok, everything goes well.\n");
	return 0;
}
