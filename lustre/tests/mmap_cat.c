// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, Intel Corporation.
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
"       mmap <file> and cat its content\n";

static size_t getFilesize(const char *filename)
{
	struct stat st;

	if (stat(filename, &st) == -1) {
		save_errno = errno;
		perror("stat");
		exit(save_errno);
	}
	return st.st_size;
}

int main(int argc, char **argv)
{
	size_t filesize;
	int fd;
	void *mmappedData;
	int rc;

	if (argc != 2) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	filesize = getFilesize(argv[1]);

	/* Open file */
	fd = open(argv[1], O_RDONLY, 0);
	if (fd == -1) {
		save_errno = errno;
		perror("open");
		exit(save_errno);
	}

	/* Execute mmap */
	mmappedData = mmap(NULL, filesize, PROT_READ,
			   MAP_PRIVATE | MAP_POPULATE, fd, 0);
	if (mmappedData == MAP_FAILED) {
		save_errno = errno;
		perror("mmap");
		exit(save_errno);
	}

	/* Write the mmapped data to stdout (= FD #1) */
	rc = write(1, mmappedData, filesize);
	if (rc == -1) {
		save_errno = errno;
		perror("write");
		exit(save_errno);
	}

	rc = munmap(mmappedData, filesize);
	if (rc == -1) {
		save_errno = errno;
		perror("munmap");
		exit(save_errno);
	}

	rc = close(fd);
	if (rc == -1) {
		save_errno = errno;
		perror("close");
		exit(save_errno);
	}

	return 0;
}

