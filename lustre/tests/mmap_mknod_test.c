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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, Intel Corporation.
 *
 * Copyright (c) 2019, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>

int save_errno;

char usage[] =
"Usage: %s <file>\n"
"       mknod, truncate to larger size, open, and mmap file";

int main(int argc, char **argv)
{
	void *mmappedData;
	int rc;

	if (argc != 2) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	/* Create file without striping */
	rc = mknod(argv[1], S_IFREG | 0666, 0);
	if (rc) {
		save_errno = errno;
		perror("mknod");
		exit(save_errno);
	}

	/* use truncate to extend file size */
	rc = truncate(argv[1], 4096);
	if (rc) {
		save_errno = errno;
		perror("mknod");
		exit(save_errno);
	}

	rc = open(argv[1], O_RDONLY);
	if (rc < 0) {
		save_errno = errno;
		perror("mknod");
		exit(save_errno);
	}

	/* mmap of file without striping should work */
	mmappedData = mmap(NULL, 4096, PROT_READ,
			   MAP_SHARED, rc, 0);
	if (mmappedData == MAP_FAILED) {
		save_errno = errno;
		perror("mknod");
		exit(save_errno);
	}

	return 0;
}

