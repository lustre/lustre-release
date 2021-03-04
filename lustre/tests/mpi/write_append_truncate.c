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
 * lustre/tests/write_append_truncate.c
 *
 * Each loop does 3 things:
 *   - truncate file to zero (not via ftruncate though, to test O_APPEND)
 *   - write a "chunk" of data (should be at file offset 0 after truncate)
 *   - on each of two threads either append or truncate-up the file
 *
 * If the truncate happened first, we should have a hole in the file.
 * If the append happened first, we should have truncated the file down.
 *
 * WRITE_SIZE_MAX and APPEND_SIZE_MAX are large enough to cross a stripe.
 *
 * compile: mpicc -g -Wall -o write_append_truncate write_append_truncate.c
 * run:     mpirun -np 2 -machlist <hostlist file> write_append_truncate <file>
 *  or:     pdsh -w <two hosts> write_append_truncate <file>
 *  or:     prun -n 2 [-N 2] write_append_truncate <file>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "mpi.h"

#define DEFAULT_ITER    10000

#define WRITE_SIZE_MAX  1234567
#define APPEND_SIZE_MAX 1234567
#define TRUNC_SIZE_MAX  1234567

#define STATUS_FMT "WR %c %7d/%#08x, AP %c %7d/%#08x, TR@ %7d/%#08x"

#define HOSTNAME_SIZE 50
char hostname[HOSTNAME_SIZE];
#define FNAMES_MAX 256

void usage(char *prog)
{
	printf("usage: %s [-a append_max] [-C] [-n nloops] [-s seed]\n\t\t[-t trunc_max] [-T] [-v] [-w write_max] <filename> ...\n",
	       prog);
	printf("\t-a append_max: maximum size of append, default %u bytes\n",
	       APPEND_SIZE_MAX);
	printf("\t-C: 'classic' checks (on file 0)\n");
	printf("\t-n nloops: count of loops to run, default %u\n",
	       DEFAULT_ITER);
	printf("\t-s seed: random seed to use, default {current time}\n");
	printf("\t-t trunc_max: maximum size of truncate, default %u bytes\n",
	       TRUNC_SIZE_MAX);
	printf("\t-T: 'classic' truncates (on file 0)\n");
	printf("\t-w write_max: maximum size of write, default %u bytes\n",
	       WRITE_SIZE_MAX);
	printf("\t-W: 'classic' writes (on rank 0, file 0)\n");
	printf("\t-v: run in verbose mode (repeat for more verbosity)\n");
	printf("\tfilename for each mountpoint of same filesystem on a node\n");
	printf("\b%s must be run with at least 2 processes\n", prog);

	MPI_Finalize();
	exit(1);
}

/* Print process rank, loop count, message, and exit (i.e. a fatal error) */
void rprintf(int rank, int loop, int error, const char *fmt, ...)
__attribute__ ((format (printf, 4, 5)));

void rprintf(int rank, int loop, int error, const char *fmt, ...)
{
	va_list ap;

	printf("r=%2u", rank);
	if (loop >= 0)
		printf(" l=%04u", loop);
	if (error != 0)
		printf(" %s", hostname);
	printf(": ");

	va_start(ap, fmt);

	vprintf(fmt, ap);

	if (error != 0)
		MPI_Abort(MPI_COMM_WORLD, error);
}

int main(int argc, char *argv[])
{
	int n, nloops = DEFAULT_ITER;
	int nfnames = 0, ifnames, fd;
	int rank = -1, nproc, ret;
	unsigned int write_max = WRITE_SIZE_MAX;
	unsigned int append_max = APPEND_SIZE_MAX;
	unsigned int write_size = 0, append_size = 0, trunc_size = 0;
	unsigned int trunc_max = 0, trunc_offset = 0;
	char *append_buf;
	char *write_buf;
	char *read_buf = NULL;
	char *trunc_buf = NULL;
	int seed = time(0);
	int done;
	int error;
	int verbose = 0;
	int classic_check = 0, classic_trunc = 0, classic_write = 0;
	char write_char = 'A', append_char = 'a';
	char *fnames[FNAMES_MAX], *end;
	char *prog = "write_append_truncate";
	int c;

	error = MPI_Init(&argc, &argv);
	if (error != MPI_SUCCESS)
		printf("%s: MPI_Init failed: %d\n", prog, error);
	else if (verbose > 2)
		printf("%s: MPI_Init succeeded\n", prog);

	prog = strrchr(argv[0], '/');
	if (!prog)
		prog = argv[0];
	else
		prog++;

	while ((c = getopt(argc, argv, "a:cCn:s:t:Tvw:W")) != -1) {
		switch (c) {
		case 'a':
			append_max = strtoul(optarg, &end, 0);
			if (append_max < 2 || *end) {
				fprintf(stderr, "%s: bad append option '%s'\n",
					prog, optarg);
				usage(prog);
			}
			break;
		case 'C':
			classic_check++;
			break;
		case 'n':
			nloops = strtoul(optarg, &end, 0);
			if (nloops == 0 || *end) {
				fprintf(stderr, "%s: bad nloops option '%s'\n",
					prog, optarg);
				usage(prog);
			}
			break;
		case 's':
			seed = strtoul(optarg, &end, 0);
			if (*end) {
				fprintf(stderr, "%s: bad seed option '%s'\n",
					prog, optarg);
				usage(prog);
			}
			break;
		case 't':
			trunc_max = strtoul(optarg, &end, 0);
			if (*end) {
				fprintf(stderr,
					"%s: bad truncate option '%s'\n", prog,
					optarg);
				usage(prog);
			}
			break;
		case 'T':
			classic_trunc++;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			write_max = strtoul(optarg, &end, 0);
			if (write_max < 2 || *end) {
				fprintf(stderr, "%s: bad write option '%s'\n",
					prog, optarg);
				usage(prog);
			}
			break;
		case 'W':
			classic_write++;
			break;
		default:
			fprintf(stderr, "%s: unknown option '%c'\n", prog, c);
			usage(prog);
		}
	}

	srand(seed);

	if (argc == optind) {
		fprintf(stderr, "%s: missing filename argument\n", prog);
		usage(prog);
	}

	if (argc > optind + FNAMES_MAX) {
		fprintf(stderr, "%s: too many extra options\n", prog);
		usage(prog);
	}

	while (optind < argc)
		fnames[nfnames++] = argv[optind++];

	error = MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	if (verbose > 2 || error != MPI_SUCCESS)
		rprintf(rank, -1, error != MPI_SUCCESS, "MPI_Comm_rank: %d\n",
			error);

	error = MPI_Comm_size(MPI_COMM_WORLD, &nproc);
	if (verbose > 2 || error != MPI_SUCCESS)
		rprintf(rank, -1, error != MPI_SUCCESS, "MPI_Comm_size: %d\n",
			error);

	if (nproc < 2)
		rprintf(rank, -1, 1, "%s: must run with at least 2 processes\n",
			prog);

	append_buf = malloc(append_max);
	if (!append_buf)
		rprintf(rank, -1, 1, "%s: error allocating append_buf %u\n",
			prog, append_max);

	write_buf = malloc(write_max);
	if (!write_buf)
		rprintf(rank, -1, 1, "%s: error allocating write_buf %u\n",
			prog, write_max);

	if (gethostname(hostname, HOSTNAME_SIZE) < 0)
		rprintf(rank, -1, 1, "%s: gethostname failed: %s\n",
			prog, strerror(errno));

	if (rank == 0) {
		int max_size = write_max + (trunc_max ?: append_max) +
			       append_max;

		fd = open(fnames[0], O_WRONLY | O_CREAT | O_TRUNC, 0666);
		rprintf(rank, -1, fd < 0,
			"create %s, max size: %u, seed %u: %s\n", fnames[0],
			max_size, seed, strerror(errno));
		close(fd);

		trunc_buf = calloc(1, trunc_max ?: append_max);
		if (!trunc_buf)
			rprintf(rank, -1, 1,
				"%s: error allocating trunc_buf %u\n",
				prog, trunc_max ?: append_max);

		/* initial write + truncate up + append */
		read_buf = malloc(max_size);
		if (!read_buf)
			rprintf(rank, -1, 1,
				"%s: error allocating read_buf %u\n",
				prog, max_size);
	}

	error = MPI_Barrier(MPI_COMM_WORLD);
	if (verbose > 2 || error != MPI_SUCCESS)
		rprintf(rank, -1, error != MPI_SUCCESS,
			"prep MPI_Barrier: %d\n", error);

	ifnames = rank % nfnames;
	fd = open(fnames[ifnames], O_RDWR | O_APPEND);
	if (verbose || fd < 0)
		rprintf(rank, -1, errno, "open '%s' (%u): %s\n",
			fnames[ifnames], ifnames, strerror(errno));

	for (n = 0; n < nloops; n++) {
		/* Initialized only to quiet stupid GCC warnings */
		unsigned int append_rank = n, trunc_rank = n + 1;
		unsigned int write_rank = 0;
		unsigned int mpi_shared_vars[6];

		/* reset the environment */
		write_char = 'A' + (n % 26);
		append_char = 'a' + (n % 26);

		if (rank == 0) {
			write_size = (rand() % (write_max - 1)) + 1;
			append_size = (rand() % (append_max - 1)) + 1;
			trunc_size = (append_size == 1) ? 1 :
				      (rand() %
				      ((trunc_max ?: append_size) - 1)) + 1;
			trunc_offset = write_size + trunc_size;

			if (verbose || n % 1000 == 0)
				rprintf(rank, n, 0, STATUS_FMT"\n",
					write_char, write_size, write_size,
					append_char, append_size, append_size,
					trunc_offset, trunc_offset);

			write_rank = (classic_write ? 0 : rand()) % nproc;
			do {
				append_rank = (classic_write ? n : rand()) %
					       nproc;
				/*
				 * We can't allow the append rank be the same
				 * as the classic_trunc trunc_rank, or we will
				 * spin here forever.
				 */
			} while (append_rank == (n + 1) % nproc);
			do {
				trunc_rank = (classic_trunc ? (n + 1) :
					      rand()) % nproc;
			} while (trunc_rank == append_rank);

			mpi_shared_vars[0] = write_size;
			mpi_shared_vars[1] = append_size;
			mpi_shared_vars[2] = trunc_size;
			mpi_shared_vars[3] = write_rank;
			mpi_shared_vars[4] = append_rank;
			mpi_shared_vars[5] = trunc_rank;
		}

		error = MPI_Bcast(&mpi_shared_vars, 6,
				  MPI_INT, 0, MPI_COMM_WORLD);
		if (verbose > 2 || error != MPI_SUCCESS)
			rprintf(rank, n, error != MPI_SUCCESS,
				"MPI_Bcast mpi_shared_vars [%u, %u, %u, %u, %u, %u]: %d\n",
				mpi_shared_vars[0], mpi_shared_vars[1],
				mpi_shared_vars[2], mpi_shared_vars[3],
				mpi_shared_vars[4], mpi_shared_vars[5], error);

		if (rank != 0) {
			write_size  = mpi_shared_vars[0];
			append_size = mpi_shared_vars[1];
			trunc_size  = mpi_shared_vars[2];
			write_rank  = mpi_shared_vars[3];
			append_rank = mpi_shared_vars[4];
			trunc_rank  = mpi_shared_vars[5];

			trunc_offset = write_size + trunc_size;
		}

		if (rank == write_rank || rank == 0)
			memset(write_buf, write_char, write_max);

		if (rank == write_rank) {
			ifnames = (classic_write ? 0 : rand()) % nfnames;
			ret = truncate(fnames[ifnames], 0);
			if (verbose > 1 || ret != 0)
				rprintf(rank, n, ret,
					"initial truncate %s (%u) @ 0: %s\n",
					fnames[ifnames], ifnames,
					strerror(errno));

			done = 0;
			do {
				ret = write(fd, write_buf + done,
					    write_size - done);
				if (verbose > 1 || ret < 0) {
					rprintf(rank, n,
						ret < 0 && errno != EINTR,
						"write %d/%d @ %d: %s\n",
						ret + done, write_size, done,
						strerror(errno));
					if (ret < 0 && errno != EINTR)
						break;
				}
				if (ret > 0)
					done += ret;
			} while (done != write_size);
		}

		if (rank == append_rank || rank == 0)
			memset(append_buf, append_char, append_size);

		error = MPI_Barrier(MPI_COMM_WORLD);
		if (verbose > 2 || error != MPI_SUCCESS)
			rprintf(rank, n, error != MPI_SUCCESS,
				"start MPI_Barrier: %d\n", error);

		/* Do the race */
		if (rank == append_rank) {
			done = 0;
			do {
				ret = write(fd, append_buf + done,
					    append_size - done);
				if (ret < 0) {
					rprintf(rank, n, errno != EINTR,
						"append %u/%u: %s\n",
						ret + done, append_size,
						strerror(errno));
					if (errno != EINTR)
						break;
				} else if (verbose > 1 || ret != append_size) {
					rprintf(rank, n, ret != append_size,
						"append %u/%u\n",
						ret + done, append_size);
				}
				if (ret > 0)
					done += ret;
			} while (done != append_size);
		} else if (rank == trunc_rank) {
			/*
			 * XXX: truncating the same file descriptor as the
			 *      append on a single node causes this test
			 *      to fail currently (2009-02-01).
			 */
			ifnames = (classic_trunc ? rank : rand()) % nfnames;
			ret = truncate(fnames[ifnames], trunc_offset);
			if (verbose > 1 || ret != 0)
				rprintf(rank, n, ret,
					"truncate %s (%u) @ %u: %s\n",
					fnames[ifnames], ifnames,
					trunc_offset, strerror(errno));
		}

		error = MPI_Barrier(MPI_COMM_WORLD);
		if (verbose > 2 || error != MPI_SUCCESS)
			rprintf(rank, n, error != MPI_SUCCESS,
				"end MPI_Barrier: %d\n", error);

		error = 0;

		/* Check the result */
		if (rank == 0) {
			char *tmp_buf;
			struct stat st = { 0 };

			ifnames = classic_check ? 0 : (rand() % nfnames);
			ret = stat(fnames[ifnames], &st);
			if (verbose > 1 || ret != 0)
				rprintf(rank, n, ret,
					"stat %s (%u) size %llu: %s\n",
					fnames[ifnames], ifnames,
					(long long)st.st_size, strerror(errno));

			ret = lseek(fd, 0, SEEK_SET);
			if (ret != 0)
				rprintf(rank, n, ret, "lseek 0: %s\n",
					strerror(errno));

			done = 0;
			do {
				ret = read(fd, read_buf + done,
					   st.st_size - done);
				if (verbose > 1 || ret <= 0) {
					rprintf(rank, n, ret <= 0,
						"read %d/%llu @ %u: %s\n",
						ret,
						(long long)st.st_size - done,
						done, ret != 0 ?
						strerror(errno) : "short read");
				}
				done += ret;
			} while (done != st.st_size);

			if (memcmp(read_buf, write_buf, write_size)) {
				rprintf(rank, n, 0,
					"WRITE bad [0-%d]/[0-%#x] != %c\n",
					write_size - 1, write_size - 1,
					write_char);
				error = 1;
			}

			tmp_buf = read_buf + write_size;

			if (st.st_size == trunc_offset) {
				/* Check case 1: first append then truncate */
				int tmp_size, tmp_offset;

				tmp_size = trunc_size < append_size ?
						trunc_size : append_size;
				tmp_offset = write_size + tmp_size;

				if (memcmp(tmp_buf, append_buf, tmp_size)) {
					rprintf(rank, n, 0,
						"trunc-after-APPEND bad [%d-%d]/[%#x-%#x] != %c\n",
						write_size, tmp_offset - 1,
						write_size, tmp_offset - 1,
						append_char);
					error = 1;
				} else if (trunc_size > append_size &&
					   memcmp(tmp_buf + append_size,
						  trunc_buf,
						  trunc_size - append_size)) {
					rprintf(rank, n, 0,
						"TRUNC-after-append bad [%d-%d]/[%#x-%#x] != 0\n",
						tmp_offset, trunc_offset - 1,
						tmp_offset, trunc_offset - 1);
					error = 1;
				}
			} else {
				int expected_size = trunc_offset + append_size;
				/* Check case 2: first truncate then append */
				if (st.st_size != expected_size) {
					rprintf(rank, n, 0,
						"APPEND-after-trunc bad file size %llu != %u\n",
						(long long)st.st_size,
						expected_size);
					error = 1;
				}

				if (memcmp(tmp_buf, trunc_buf, trunc_size)) {
					rprintf(rank, n, 0,
						"append-after-TRUNC bad [%d-%d]/[%#x-%#x] != 0\n",
						write_size, trunc_offset - 1,
						write_size, trunc_offset - 1);
					error = 1;
				} else if (memcmp(read_buf + trunc_offset,
						  append_buf, append_size)) {
					rprintf(rank, n, 0,
						"APPEND-after-trunc bad [%d-%d]/[%#x-%#x] != %c\n",
						trunc_offset, expected_size - 1,
						trunc_offset, expected_size - 1,
						append_char);
					error = 1;
				}
			}

			if (error == 1) {
				char command[4096];

				rprintf(rank, n, 0, STATUS_FMT"\n",
					write_char, write_size, write_size,
					append_char, append_size, append_size,
					trunc_offset, trunc_offset);

				sprintf(command, "od -Ax -a %s", fnames[0]);
				ret = system(command);
				MPI_Abort(MPI_COMM_WORLD, 1);
			}
		}
	}

	if (rank == 0 || verbose)
		printf("r=%2u n=%4u: "STATUS_FMT"\nPASS\n", rank, n - 1,
		       write_char, write_size, write_size, append_char,
		       append_size, append_size, trunc_offset, trunc_offset);

	close(fd);

	if (rank == 0) {
		ifnames = rand() % nfnames;
		ret = unlink(fnames[ifnames]);
		if (ret != 0)
			printf("%s: unlink %s failed: %s\n",
			       prog, fnames[ifnames], strerror(errno));
	}

	MPI_Finalize();
	return 0;
}
