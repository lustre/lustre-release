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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/reads.c
 *
 * Lustre Reads test
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#define _XOPEN_SOURCE 500 /* for pread(2) */

#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>

static void usage(void)
{
	printf("reads: read random or stride chunks of a file.\n");
	printf("Usage:\n\n");
	printf("reads -f <filename> -s <filesize> -b <buffersize> -a <adjacent reads> [-v] [-h] [-C] [-l <stride_length> ] [ -o <stride_offset> ] [-S <seed>] [-n <iterations>][-w <width>] [-t <timelimit>]\n");
}

enum {
	BSIZE_DEFAULT = 16 * 4096
};

#define LOG(level, ...)				\
({						\
	if ((level) <= verbosity)		\
		fprintf(stderr, __VA_ARGS__);	\
})

enum {
	LOG_CRIT,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG
};

enum {
	RR_OK,
	RR_PARSE,
	RR_SET,
	RR_MALLOC,
	RR_OPEN,
	RR_PRECLEAN,
	RR_READ
};

int main(int argc, char **argv)
{
	int    verbosity = LOG_CRIT;
	char  *fname = NULL;
	loff_t size = 0;
	size_t bsize = 0;
	int    ad = 1;
	int    preclean = 0;
	int    width = 10;
	unsigned int seed = 0;
	unsigned long iterations = 0;
	unsigned long timelimit = 24 * 3600;
	unsigned long stride_length = 0;
	unsigned long stride_offset = 0;

	int opt;
	int fd;
	unsigned long nblocks;
	unsigned long i;
	ssize_t  ret;

	struct timeval start;
	struct timeval stop;

	double usecs;

	char *buf;
	char *term;

	do {
		opt = getopt(argc, argv, "f:s:b:va:hCS:n:t:l:o:w:");
		switch (opt) {
		case -1:
			break;
		default:
			LOG(LOG_CRIT, "Unable to parse command line.\n");
		case 'h':
			usage();
			return RR_PARSE;
		case 'v':
			verbosity ++;
			break;
		case 'f':
			fname = strdup(optarg);
			break;
		case 's':
			size = strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse size %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;
		case 'b':
			bsize = strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse bsize %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;
		case 'a':
			ad = (int)strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse ad %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;
		case 'C':
			preclean = 1;
			break;
		case 'S':
			seed = strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse seed %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;
		case 'n':
			iterations = strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse seed %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;

			break;
		case 't':
			timelimit = strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse seed %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;
                case 'l':
                        stride_length = strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse seed %s\n", optarg);
				usage();
				return RR_SET;
			}
	       		break;
		case 'o':
			stride_offset = strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse seed %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;
		case 'w':
			width = (int)strtol(optarg, &term, 0);
			if (term == optarg) {
				fprintf (stderr, "Can't parse seed %s\n", optarg);
				usage();
				return RR_SET;
			}
			break;
		}
	} while (opt != -1);

	if (fname == NULL || size == 0 || bsize == 0 || ad <= 0) {
		usage();
		return RR_SET;
	}

	bsize /= ad;
	nblocks = size / bsize;
	buf = malloc(bsize);
	if (buf == NULL) {
		LOG(LOG_CRIT, "malloc(%lu) failure: %s\n", (long)bsize,
		    strerror(errno));
		return RR_MALLOC;
	}

	fd = open(fname, (preclean ? O_RDWR : O_RDONLY) | O_CREAT, 0700);
	if (fd == -1) {
		LOG(LOG_CRIT, "malloc(\"%s\") failure: %s\n", fname,
		    strerror(errno));
		return RR_OPEN;
	}
	if (preclean) {
		loff_t towrite;
		size_t count;

		LOG(LOG_INFO, "precleaning");
		for (i = 0, towrite = size; towrite > 0; towrite -= ret) {
			count = bsize < towrite ? bsize : towrite;
			memset(buf, bsize, seed + i++);
			ret = write(fd, buf, count);
			if (ret < 0) {
				LOG(LOG_CRIT, "write() failure: %s\n",
				    strerror(errno));
				close(fd);
				return RR_PRECLEAN;
			}
		}
	}
	if (seed != 0)
		srand(seed);
	gettimeofday(&start, NULL);
	timelimit += start.tv_sec;
	for (i = 0; !iterations || i < iterations; i ++) {
		unsigned long block_nr;
		int j;

		if (stride_length) 
			block_nr = (unsigned long)(i*stride_length + 
						   stride_offset) % nblocks;
		else
			block_nr = (unsigned long)((double)nblocks*rand()/
						   (RAND_MAX+1.0));
		if (i % width == 0)
			LOG(LOG_INFO, "\n%9lu: ", i);
		LOG(LOG_INFO, "%7lu ", block_nr);
		for (j = 0; j < ad; j++) {
			ret = pread(fd, buf, bsize, (block_nr + j) * bsize);
			if (ret != bsize) {
				LOG(LOG_CRIT,
				    "pread(...%zi, %li) got: %zi, %s\n", bsize,
				    block_nr * bsize, ret, strerror(errno));
				close(fd);
				return RR_READ;
			}
		}
		gettimeofday(&stop, NULL);
		if (stop.tv_sec > timelimit)
			break;
	}
	close(fd);
	usecs = (stop.tv_sec - start.tv_sec) * 1000000. +
		stop.tv_usec - start.tv_usec;
	printf("\n%fs, %gMB/s\n", usecs / 1000000.,
	       (double)bsize * ad * i / usecs);
	return RR_OK;
}
