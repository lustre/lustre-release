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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

#define T1 "write data before unlink\n"
#define T2 "write data after unlink\n"
char buf[128];

int main(int argc, char **argv)
{
	char *fname, *fname2;
	struct stat st;
	int fd, rc;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: %s filename [filename2]\n", argv[0]);
		exit(1);
	}

	fname = argv[1];
	if (argc == 3)
		fname2 = argv[2];
	else
		fname2 = argv[1];

	fprintf(stderr, "opening\n");
	fd = open(fname, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (fd == -1) {
		fprintf(stderr, "open (normal) %s\n", strerror(errno));
		exit(1);
	}

	fprintf(stderr, "writing\n");
	rc = write(fd, T1, strlen(T1) + 1);
	if (rc != strlen(T1) + 1) {
		fprintf(stderr, "write (normal) %s (rc %d)\n",
			strerror(errno), rc);
		exit(1);
	}

	if (argc == 3) {
		fprintf(stderr, "unlinking %s\n", fname2);
		rc = unlink(fname2);
		if (rc) {
			fprintf(stderr, "unlink %s\n", strerror(errno));
			exit(1);
		}
	} else {
		printf("unlink %s and press enter\n", fname);
		getc(stdin);
	}

	fprintf(stderr, "accessing (1)\n");
	if (access(fname, F_OK) == 0) {
		fprintf(stderr, "%s still exists\n", fname);
		exit(1);
	}

	fprintf(stderr, "seeking (1)\n");
	rc = lseek(fd, 0, SEEK_SET);
	if (rc) {
		fprintf(stderr, "seek %s\n", strerror(errno));
		exit(1);
	}

	fprintf(stderr, "accessing (2)\n");
	if (access(fname, F_OK) == 0) {
		fprintf(stderr, "%s still exists\n", fname);
		exit(1);
	}

	fprintf(stderr, "fstat...\n");
	rc = fstat(fd, &st);
	if (rc) {
		fprintf(stderr, "fstat (unlink) %s\n", strerror(errno));
		exit(1);
	}
	if (st.st_nlink != 0)
		fprintf(stderr, "st_nlink = %d\n", (int)st.st_nlink);

	fprintf(stderr, "reading\n");
	rc = read(fd, buf, strlen(T1) + 1);
	if (rc != strlen(T1) + 1) {
		fprintf(stderr, "read (unlink) %s (rc %d)\n",
			strerror(errno), rc);
		exit(1);
	}

	fprintf(stderr, "comparing data\n");
	if (memcmp(buf, T1, strlen(T1) + 1)) {
		fprintf(stderr, "FAILURE: read wrong data after unlink\n");
		exit(1);
	}

	fprintf(stderr, "truncating\n");
	rc = ftruncate(fd, 0);
	if (rc) {
		fprintf(stderr, "truncate (unlink) %s\n", strerror(errno));
		exit(1);
	}

	fprintf(stderr, "seeking (2)\n");
	rc = lseek(fd, 0, SEEK_SET);
	if (rc) {
		fprintf(stderr, "seek (after unlink trunc) %s\n",
			strerror(errno));
		exit(1);
	}

	fprintf(stderr, "writing again\n");
	rc = write(fd, T2, strlen(T2) + 1);
	if (rc != strlen(T2) + 1) {
		fprintf(stderr, "write (after unlink trunc) %s (rc %d)\n",
			strerror(errno), rc);
		exit(1);
	}

	fprintf(stderr, "seeking (3)\n");
	rc = lseek(fd, 0, SEEK_SET);
	if (rc) {
		fprintf(stderr, "seek (before unlink read) %s\n",
			strerror(errno));
		exit(1);
	}

	fprintf(stderr, "reading again\n");
	rc = read(fd, buf, strlen(T2) + 1);
	if (rc != strlen(T2) + 1) {
		fprintf(stderr, "read (after unlink rewrite) %s (rc %d)\n",
			strerror(errno), rc);
		exit(1);
	}

	fprintf(stderr, "comparing data again\n");
	if (memcmp(buf, T2, strlen(T2) + 1)) {
		fprintf(stderr, "FAILURE: read wrong data after rewrite\n");
		exit(1);
	}

	fprintf(stderr, "closing\n");
	rc = close(fd);
	if (rc) {
		fprintf(stderr, "close (unlink) %s\n", strerror(errno));
		exit(1);
	}

	fprintf(stderr, "SUCCESS - goto beer\n");
	return 0;
}
