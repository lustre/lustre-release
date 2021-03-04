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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/rwv.c
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <lustre/lustreapi.h>

#define ACT_NONE        0
#define ACT_READ        1
#define ACT_WRITE       2
#define ACT_SEEK        4
#define ACT_READHOLE    8
#define ACT_VERIFY      16
#define ACT_OUTPUT	32

void usage()
{
	printf("usage: rwv -f filename <-r|-w> [-a] [-z] [-d] [-v]");
	printf(" [-s offset] [-o[outf]] -n iovcnt SIZE1 SIZE2 SIZE3...\n");
	printf("-a  append IO (O_APPEND)\n");
	printf("-r  file read (O_RDONLY)\n");
	printf("-w  file write (O_WRONLY)\n");
	printf("-s  set the start pos of the read/write test\n");
	printf("-z  test for read hitting hole\n");
	printf("-d  create flags (O_LOV_DELAY_CREATE)\n");
	printf("-v  verify the data content of read\n");
	printf("-o  write the file content of read to an optional file\n");
}

int data_verify(struct iovec *iov, int iovcnt, char c)
{
	int i;

	for (i = 0; i < iovcnt; i++) {
		size_t count = iov[i].iov_len;
		char *s = iov[i].iov_base;

		for (; count > 0; ++s, count--) {
			if (*s != c) {
				printf("Data mismatch %x: %x\n", *s, c);
				return 1;
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	int c;
	int fd;
	int rc = 0;
	int flags = 0;
	int iovcnt = 0;
	int act = ACT_NONE;
	int out_fd = -1;
	char pad = 0xba;
	char *end;
	char *fname = "FILE";
	unsigned long len = 0;
	struct iovec *iov;
	off64_t offset = 0;

	while ((c = getopt(argc, argv, "f:n:s:rwahvdzo::")) != -1) {
		switch (c) {
		case 'f':
			fname = optarg;
			break;
		case 'n':
			iovcnt = strtoul(optarg, &end, 0);
			if (*end) {
				printf("Bad iov count: %s\n", optarg);
				return 1;
			}
			if (iovcnt > UIO_MAXIOV || iovcnt <= 0) {
				printf("Wrong iov count\n");
				return 1;
			}
			break;
		case 's':
			act |= ACT_SEEK;
			offset = strtoull(optarg, &end, 0);
			if (*end) {
				printf("Bad seek offset: %s\n", optarg);
				return 1;
			}
			break;
		case 'w':
			act |= ACT_WRITE;
			flags |= O_WRONLY | O_CREAT;
			break;
		case 'r':
			act |= ACT_READ;
			flags |= O_RDONLY;
			break;
		case 'a':
			flags |= O_APPEND;
			break;
		case 'd':
			flags |= O_LOV_DELAY_CREATE;
			break;
		case 'z':
			pad = 0;
			act |= ACT_READHOLE;
			break;
		case 'v':
			act |= ACT_VERIFY;
			break;
		case 'o':
			act |= ACT_OUTPUT;
			if (optarg)
				out_fd = open(optarg, O_WRONLY | O_CREAT, 0644);
			else
				out_fd = fileno(stdout);
			break;
		case 'h':
			usage();
			break;
		}
	}

	if (act == ACT_NONE) {
		usage();
		return 1;
	}

	if ((act & ACT_READ) &&  (act & ACT_WRITE)) {
		printf("Read and write test should be exclusive\n");
		return 1;
	}

	if (act & ACT_OUTPUT && (!(act & ACT_READ) || out_fd < 0)) {
		printf("-o not in read mode or cannot open the output file");
		return 1;
	}

	if (argc - optind < iovcnt) {
		printf("Not enough parameters for iov size\n");
		return 1;
	}

	iov = (struct iovec *)malloc(iovcnt * sizeof(struct iovec));
	if (!iov) {
		printf("No memory %s\n", strerror(errno));
		return 1;
	}

	for (c = 0; c < iovcnt; c++) {
		struct iovec *iv = &iov[c];

		iv->iov_len = strtoul(argv[optind++], &end, 0);
		if (*end) {
			printf("Error iov size\n");
			rc = 1;
			goto out;
		}
		iv->iov_base = mmap(NULL, iv->iov_len, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANON, 0, 0);
		if (iv->iov_base == MAP_FAILED) {
			printf("No memory %s\n", strerror(errno));
			rc = 1;
			goto out;
		}
		if (act & ACT_WRITE)
			memset(iv->iov_base, pad, iv->iov_len);
		len += iv->iov_len;
	}

	fd = open(fname, O_LARGEFILE | flags, 0644);
	if (fd == -1) {
		printf("Cannot open %s:%s\n", fname, strerror(errno));
		return 1;
	}

	if ((act & ACT_SEEK) && (lseek64(fd, offset, SEEK_SET) < 0)) {
		printf("Cannot seek %s\n", strerror(errno));
		rc = 1;
		goto out;
	}

	if (act & ACT_WRITE) {
		rc = writev(fd, iov, iovcnt);
		if (rc != len) {
			printf("Write error: %s (rc = %d, len = %ld)\n",
			       strerror(errno), rc, len);
			rc = 1;
			goto out;
		}
	} else if (act & ACT_READ) {
		rc = readv(fd, iov, iovcnt);
		if (rc != len) {
			printf("Read error: %s rc = %d\n", strerror(errno), rc);
			rc = 1;
			goto out;
		}

		/* It should return zeroed buf if the read hits hole.*/
		if (((act & ACT_READHOLE) || (act & ACT_VERIFY)) &&
		    data_verify(iov, iovcnt, pad)) {
			rc = 1;
			goto out;
		}

		if (act & ACT_OUTPUT) {
			rc = writev(out_fd, iov, iovcnt);
			if (rc != len) {
				printf("write error: %s rc = %d\n",
				       strerror(errno), rc);
				rc = 1;
				goto out;
			}
		}
	}

	rc = 0;
out:
	if (iov)
		free(iov);
	if (out_fd >= 0)
		close(out_fd);
	return rc;
}
