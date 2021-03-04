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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/mpi/cascading_rw.c
 *
 * Author: You Feng <youfeng@clusterfs.com>
 */

#include <config.h>
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <asm/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <errno.h>

#include <lustre/lustreapi.h>
#include "lp_utils.h"
#ifndef _IOWR
# include <ioctl.h>
#endif


int rank = 0;
int size = 0;

char *testdir = NULL;

void rw_file(char *name, long stride, unsigned int seed)
{
	char filename[MAX_FILENAME_LEN];
	char *buf, *o_buf;
	struct lov_user_md lum = {0};
	int fd, rc, i, bad = 0, root = 0;
	long off;
	long page_size = sysconf(_SC_PAGESIZE);

	sprintf(filename, "%s/%s", testdir, name);

	if (rank == 0) {
		remove_file_or_dir(filename);

		lum.lmm_magic = LOV_USER_MAGIC;
		lum.lmm_stripe_size = 0;
		lum.lmm_stripe_count = 0;
		lum.lmm_stripe_offset = -1;

		fd = open(filename, O_CREAT | O_RDWR | O_LOV_DELAY_CREATE,
			FILEMODE);
		if (fd == -1)
			FAILF("open of file %s", filename);

		rc = ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum);
		if (rc == -1)
			FAILF("ioctl SETSTRIPE of file %s", filename);

		if (close(fd) == -1)
			FAILF("close of file %s", filename);
	}

	MPI_Barrier(MPI_COMM_WORLD);

	if (stride < 0) {
		if (rank == 0) {
			srandom(seed);
			while (stride < page_size/2) {
				stride = random();
				stride -= stride % 16;
				if (stride < 0)
					stride = -stride;
				stride %= 2 * lum.lmm_stripe_size;
			}
		}

		MPI_Barrier(MPI_COMM_WORLD);

		MPI_Bcast(&stride, 1, MPI_LONG, root, MPI_COMM_WORLD);
	}

	MPI_Barrier(MPI_COMM_WORLD);

	buf = (char *)malloc(stride);
	if (!buf)
		FAILF("malloc of buf with size %ld", stride);

	if (rank == 0) {
		fd = open(filename, O_RDWR);
		if (fd == -1)
			FAILF("open of file %s", filename);

		off = 0;
		fill_stride(buf, stride, 0, off);
		rc = write(fd, buf, stride);
		if (rc != stride)
			FAILF("write of file %s return %d", filename, rc);

		off += stride;
		while (off < size * stride) {
			fill_stride(buf, stride, 0x8080808080808080ULL, off);
			rc = write(fd, buf, stride);
			if (rc != stride)
				FAILF("write of file %s return %d",
				      filename, rc);
			off += stride;
		}

		if (close(fd) == -1)
			FAILF("close of file %s", filename);
	}

	MPI_Barrier(MPI_COMM_WORLD);

	o_buf = (char *)malloc(stride);
	if (!o_buf)
		FAILF("malloc of o_buf with size %ld", stride);

	fd = open(filename, O_RDWR);
	if (fd == -1)
		FAILF("open of file %s", filename);

	off = 0;
	for (i = 1; i < size; ++i) {
		if (rank == i) {
			rc = lseek(fd, off, SEEK_SET);
			if (rc != off)
				FAILF("lseek of file %s return %d",
				      filename, rc);

			rc = read(fd, buf, stride);
			if (rc != stride) {
				if (rc > 0) {
					fill_stride(o_buf, rc, i - 1, off);
					dump_diff(o_buf, buf, rc, off);
				}
				FAILF("read of file %s return %d",
				      filename, rc);
			}

			fill_stride(o_buf, stride, i - 1, off);
			if (memcmp(o_buf, buf, stride) != 0) {
				dump_diff(o_buf, buf, stride, off);
				errno = 0;
				FAILF("Error: diff data read from %s",
				      filename);
			}
		}

		off += stride;

		if (rank == i) {
			fill_stride(buf, stride, i, off);
			rc = write(fd, buf, stride);
			if (rc != stride)
				FAILF("write of file %s return %d",
				      filename, rc);
		}

		MPI_Barrier(MPI_COMM_WORLD);
	}

	if (close(fd) == -1)
		FAILF("close of file %s", filename);

	MPI_Barrier(MPI_COMM_WORLD);

	if (rank == 0) {
		fd = open(filename, O_RDONLY);
		if (fd == -1)
			FAILF("open of file %s", filename);

		off = 0;
		for (i = 0; i < size; ++i) {
			rc = read(fd, buf, stride);
			if (rc != stride) {
				if (rc > 0) {
					fill_stride(o_buf, rc, i, off);
					dump_diff(o_buf, buf, rc, off);
				}
				FAILF("read of file %s", filename);
			}

			fill_stride(o_buf, stride, i, off);
			if (memcmp(o_buf, buf, stride) != 0) {
				bad = 1;
				dump_diff(o_buf, buf, stride, off);
			}
			off += stride;
		}
		if (bad == 1) {
			errno = 0;
			FAILF("Error: diff data read from %s", filename);
		}
	}

	MPI_Barrier(MPI_COMM_WORLD);
	fprintf(stderr, "passed barrier 5\n");

	free(buf);
	free(o_buf);
}

void cascading_rw(long stride, unsigned int seed)
{
	begin("setup");
	end("setup");

	begin("test");
	rw_file("cascading_rw", stride, seed);
	end("test");

	begin("cleanup");
	remove_file("cascading_rw");
	end("cleanup");
}

void usage(char *proc)
{
	int i;

	if (rank == 0) {
		printf("Usage: %s [-h] -d <testdir> [-s \"1024\"]\n", proc);
		printf("           [-n \"13\"] [-e \"12345\"]\n");
		printf("           [-v] [-V #] [-g]\n");
		printf("\t-h: prints this help message\n");
		printf("\t-d: the directory in which the tests will run\n");
		printf("\t-s: process stride size\n");
		printf("\t-n: repeat test # times\n");
		printf("\t-n: random seed, used to re-create previous runs\n");
		printf("\t-v: increase the verbositly level by 1\n");
		printf("\t-V: select a specific verbosity level\n");
		printf("\t-g: debug mode\n");
	}

	MPI_Initialized(&i);
	if (i)
		MPI_Finalize();
	exit(0);
}

int main(int argc, char *argv[])
{
	int i, iterations = 16, c;
	long stride = -1;
	unsigned int seed = 0;

	/*
	 * Check for -h parameter before MPI_Init so the binary can be
	 * called directly, without, for instance, mpirun
	 */
	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
			usage(argv[0]);
	}

	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);

	/* Parse command line options */
	while (1) {
		c = getopt(argc, argv, "d:e:ghn:s:vV:");
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			testdir = optarg;
			break;
		case 'e':
			seed = (unsigned int)atoi(optarg);
			break;
		case 'g':
			debug = 1;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'n':
			iterations = atoi(optarg);
			break;
		case 's':
			stride = atol(optarg);
			break;
		case 'v':
			verbose += 1;
			break;
		case 'V':
			verbose = atoi(optarg);
			break;
		}
	}

	if (rank == 0)
		printf("%s is running with %d process(es) %s\n",
		       argv[0], size, debug ? "in DEBUG mode" : "\b\b");

	if (size < 2) {
		fprintf(stderr,
			"There should be at least 3 process to run the test!\n");
		MPI_Abort(MPI_COMM_WORLD, 2);
	}

	if (testdir == NULL && rank == 0) {
		fprintf(stderr,
			"Please specify a test directory! (\"%s -h\" for help)\n",
			argv[0]);
		MPI_Abort(MPI_COMM_WORLD, 2);
	}

	lp_gethostname();

	for (i = 0; i < iterations; ++i) {
		if (rank == 0)
			printf("%s: Running test #%s(iter %d)\n",
			       timestamp(), argv[0], i);

		cascading_rw(stride, seed);
		MPI_Barrier(MPI_COMM_WORLD);
	}

	if (rank == 0)
		printf("%s: All tests passed!\n", timestamp());
	MPI_Finalize();
	return 0;
}
