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
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/write_disjoint.c
 *
 * Each loop does 3 things:
 *   - rank 0 truncates to 0
 *   - all ranks agree on a random chunk size
 *   - all ranks race to write their pattern to their chunk of the file
 *   - rank 0 makes sure that the resulting file size is ranks * chunk size
 *   - rank 0 makes sure that everyone's patterns went to the right place
 *
 * compile: mpicc -g -Wall -o write_disjoint write_disjoint.c
 * run:     mpirun -np N -machlist <hostlist file> write_disjoint
 *  or:     pdsh -w <N hosts> write_disjoint
 *  or:     prun -n N [-N M] write_disjoint
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include "mpi.h"

/* Chosen arbitrarily.  Actually running this large will take a long time.*/
#define CHUNK_MAX_SIZE (1024 * 1024 * 16)

void rprintf(int rank, int loop, const char *fmt, ...)
{
	va_list ap;

	printf("rank %d, loop %d: ", rank, loop);

	va_start(ap, fmt);

	vprintf(fmt, ap);

	MPI_Abort(MPI_COMM_WORLD, -1); /* This will exit() according to man */
}

#define CHUNK_SIZE(n) chunk_size[(n) % 2]

int main(int argc, char *argv[])
{
	int i, n, fd, c;
	unsigned long chunk_size[2];
	int rank, noProcessors, done;
	int error;
	off_t offset;
	char **chunk_buf;
	char *read_buf;
	struct stat stat_buf;
	ssize_t ret;
	char *filename = "/mnt/lustre/write_disjoint";
	int numloops = 1000;
	int max_size = CHUNK_MAX_SIZE;
	int random = 0;
	unsigned int seed = 0;
	int seed_provided = 0;

	error = MPI_Init(&argc, &argv);
	if (error != MPI_SUCCESS)
		rprintf(-1, -1, "MPI_Init failed: %d\n", error);
	/* Parse command line options */
	while ((c = getopt(argc, argv, "f:n:m:s:")) != EOF) {
		errno = 0;
		switch (c) {
		case 'f':
			filename = optarg;
			break;
		case 'n':
			numloops = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			max_size = strtoul(optarg, NULL, 0);
			if (max_size > CHUNK_MAX_SIZE)
				rprintf(-1, -1, "Chunk size larger than %d.\n",
					CHUNK_MAX_SIZE);
			break;
		case 's':
			seed = strtoul(optarg, NULL, 0);
			seed_provided = 1;
			break;
		}
	}

	MPI_Comm_size(MPI_COMM_WORLD, &noProcessors);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);

	chunk_buf = malloc(noProcessors * sizeof(chunk_buf[0]));
	for (i = 0; i < noProcessors; i++) {
		chunk_buf[i] = malloc(max_size);
		memset(chunk_buf[i], 'A' + i, max_size);
	}
	read_buf = malloc(noProcessors * max_size);

	if (rank == 0) {
		fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (fd < 0)
			rprintf(rank, -1, "open() returned %s\n",
				strerror(errno));
	}
	MPI_Barrier(MPI_COMM_WORLD);

	fd = open(filename, O_RDWR);
	if (fd < 0)
		rprintf(rank, -1, "open() returned %s\n", strerror(errno));

	if (rank == 0) {
		if (!seed_provided)
			seed = (unsigned int)time(NULL);
		printf("random seed: %d\n", seed);
		srand(seed);
	}

	for (n = 0; n < numloops; n++) {
		/* reset the environment */
		if (rank == 0) {
			ret = truncate(filename, 0);
			if (ret != 0)
				rprintf(rank, n, "truncate() returned %s\n",
					strerror(errno));

			random = rand();
		}
		MPI_Bcast(&random, 1, MPI_INT, 0, MPI_COMM_WORLD);
		CHUNK_SIZE(n) = random % max_size;

		if (n % 1000 == 0 && rank == 0)
			printf("loop %d: chunk_size %lu\n", n, CHUNK_SIZE(n));

		if (stat(filename, &stat_buf) < 0)
			rprintf(rank, n, "error stating %s: %s\n",
				filename, strerror(errno));

		if (stat_buf.st_size != 0)
			rprintf(rank, n,
				"filesize = %lu. Should be zero after truncate\n",
				stat_buf.st_size);

		MPI_Barrier(MPI_COMM_WORLD);

		/* Do the race */
		offset = rank * CHUNK_SIZE(n);
		lseek(fd, offset, SEEK_SET);

		done = 0;
		do {
			ret = write(fd, chunk_buf[rank] + done,
				    CHUNK_SIZE(n) - done);
			if (ret < 0 && errno != EINTR)
				rprintf(rank, n, "write() returned %s\n",
					strerror(errno));
			if (ret > 0)
				done += ret;
		} while (done != CHUNK_SIZE(n));

		MPI_Barrier(MPI_COMM_WORLD);

		/* Check the result */
		if (stat(filename, &stat_buf) < 0)
			rprintf(rank, n, "error stating %s: %s\n",
				filename, strerror(errno));

		if (stat_buf.st_size != CHUNK_SIZE(n) * noProcessors) {
			if (n > 0)
				printf("loop %d: chunk_size %lu, file size was %lu\n",
				       n - 1, CHUNK_SIZE(n - 1),
				       CHUNK_SIZE(n - 1) * noProcessors);
			rprintf(rank, n,
				"invalid file size %lu instead of %lu = %lu * %u\n",
				(unsigned long)stat_buf.st_size,
				CHUNK_SIZE(n) * noProcessors,
				CHUNK_SIZE(n), noProcessors);
		}

		if (rank == 0) {
			if (lseek(fd, 0, SEEK_SET) < 0)
				rprintf(rank, n, "error seeking to 0: %s\n",
					strerror(errno));

			done = 0;
			do {
				ret = read(fd, read_buf + done,
					   CHUNK_SIZE(n) * noProcessors - done);
				if (ret < 0)
					rprintf(rank, n, "read returned %s\n",
						strerror(errno));

				done += ret;
			} while (done != CHUNK_SIZE(n) * noProcessors);

			for (i = 0; i < noProcessors; i++) {
				char command[4096];
				int j;

				if (!memcmp(read_buf + (i * CHUNK_SIZE(n)),
					    chunk_buf[i], CHUNK_SIZE(n)))
					continue;

				/* print out previous chunk sizes */
				if (n > 0)
					printf("loop %d: chunk_size %lu\n",
					       n - 1, CHUNK_SIZE(n - 1));

				printf("loop %d: chunk %d corrupted with chunk_size %lu, page_size %d\n",
				       n, i, CHUNK_SIZE(n), getpagesize());
				printf("ranks:\tpage boundry\tchunk boundry\tpage boundry\n");
				for (j = 1 ; j < noProcessors; j++) {
					int b = j * CHUNK_SIZE(n);

					printf("%c -> %c:\t%d\t%d\t%d\n",
					       'A' + j - 1, 'A' + j,
					       b & ~(getpagesize() - 1), b,
					       (b + getpagesize()) &
					       ~(getpagesize() - 1));
				}

				sprintf(command, "od -Ad -a %s", filename);
				ret = system(command);
				rprintf(0, n, "data check error - exiting\n");
			}
		}
		MPI_Barrier(MPI_COMM_WORLD);
	}

	printf("Finished after %d loops\n", n);
	MPI_Finalize();
	return 0;
}
