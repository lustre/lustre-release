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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv)
{
	int fd1, fd2;
	struct stat st1, st2;

	if (argc != 3) {
		printf("Usage %s file1 file2\n", argv[0]);
		return 1;
	}

	fd1 = open(argv[1], O_CREAT | O_RDWR, 0666);
	if (fd1 == -1) {
		printf("Error opening %s: %s\n", argv[1], strerror(errno));
		return errno;
	}

	fd2 = open(argv[2], O_RDONLY);
	if (fd2 == -1) {
		printf("Error opening %s: %s\n", argv[2], strerror(errno));
		return errno;
	}

	sleep(1);

	if (write(fd1, "hello", strlen("hello")) != strlen("hello")) {
		printf("Error writing: %s\n", strerror(errno));
		return errno;
	}

	if (fstat(fd1, &st1)) {
		printf("Error statting %s: %s\n", argv[1], strerror(errno));
		return errno;
	}

	if (fstat(fd2, &st2)) {
		printf("Error statting %s: %s\n", argv[2], strerror(errno));
		return errno;
	}

	if (st1.st_size != st2.st_size) {
		printf("Sizes don't match %lu, %lu\n",
		       (unsigned long)st1.st_size,
		       (unsigned long)st2.st_size);
		return 1;
	}

	if (st1.st_mtime != st2.st_mtime) {
		printf("Mtimes don't match %ld, %ld\n",
		       st1.st_mtime, st2.st_mtime);
		return 1;
	}

	if (st1.st_blocks != st2.st_blocks) {
		printf("Blocks don't match %ld, %ld\n",
		       (long)st1.st_blocks, (long)st2.st_blocks);
		return 1;
	}

	return 0;
}
