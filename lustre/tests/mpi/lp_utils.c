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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/tests/lp_utils.c
 *
 * Author: You Feng <youfeng@clusterfs.com>
 */

#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include "lp_utils.h"

#define MAX_PROCESSES 8

int verbose;
int debug;

char hostname[1024];

struct timeval t1, t2;

char *timestamp()
{
	static char datestring[80];
	time_t timestamp;

	fflush(stdout);
	timestamp = time(NULL);
	strftime(datestring, 80, "%T", localtime(&timestamp));

	return datestring;
}

void begin(char *str)
{
	if (verbose > 0 && rank == 0) {
		gettimeofday(&t1, NULL);
		printf("%s:\tBeginning %s\n", timestamp(), str);
		fflush(stdout);
	}
}

void end(char *str)
{
	float elapsed;

	MPI_Barrier(MPI_COMM_WORLD);
	if (verbose > 0 && rank == 0) {
		gettimeofday(&t2, NULL);
		elapsed = (t2.tv_sec + ((float)t2.tv_usec / 1000000)) -
			(t1.tv_sec + ((float)t1.tv_usec / 1000000));
		if (elapsed >= 60) {
			printf("%s:\tFinished %-15s(%.2f min)\n", timestamp(),
			       str, elapsed / 60);
		} else {
			printf("%s:\tFinished %-15s(%.3f sec)\n",
			       timestamp(), str, elapsed);
		}
		fflush(stdout);
	}
}

void dump_diff(char *orig_buf, char *buf, int size, long _off)
{
	int i, diff, off;
	char *p, *end;

	printf("commpared buf size %d, at offset %lu\n\n", size, _off);

	if (orig_buf) {
		printf("original buf:\n");
		p = orig_buf;
		end = orig_buf + size;
		i = 1;
		while (p < end) {
			printf(" %8lx", *(long *)p);
			p += sizeof(long);
			if (i++ % 8 == 0)
				printf("\n");
		}
		if (i % 8)
			printf("\n\n");
		else
			printf("\n");
	}

	if (buf) {
		printf("different data: diff_data(orig_data)\n");
		diff = 0;
		off = 0;
		i = 1;
		p = buf;
		end = buf + size;
		while (p < end) {
			if (memcmp(p, orig_buf + off, sizeof(long)) != 0) {
				printf("\toff: %5d,\tdata: %8lx (%8lx)\n", off,
				       *(unsigned long *)p,
				       *(unsigned long *)(orig_buf + off));
				diff++;
			}
			off += sizeof(long);
			p += sizeof(long);
		}
		printf("\n %d total differents found\n\n", diff);
	}
}

void lp_gethostname(void)
{
	if (gethostname(hostname, 1024) == -1) {
		fprintf(stderr, "gethostname: (%d)%s", errno, strerror(errno));
		MPI_Abort(MPI_COMM_WORLD, 2);
	}
}

/*
 * This function does not FAIL if the requested "name" does not exit.
 * This is just to clean up any files or directories left over from
 * previous runs
 */
void remove_file_or_dir(char *name)
{
	struct stat statbuf;

	if (stat(name, &statbuf) != -1) {
		if (S_ISREG(statbuf.st_mode)) {
			printf("stale file found\n");
			if (unlink(name) == -1)
				FAILF("unlink of %s", name);
		}
		if (S_ISDIR(statbuf.st_mode)) {
			printf("stale directory found\n");
			if (rmdir(name) == -1)
				FAILF("rmdir of %s", name);
		}
	}
}

void create_file(char *name, long filesize, int fill)
{
	static char filename[MAX_FILENAME_LEN];
	char buf[1024 * 8];
	char c = 'A' + size;
	int fd, rc;
	short zero = 0;
	long left = filesize;

	/* Process 0 creates the test file(s) */
	if (rank == 0) {
		sprintf(filename, "%s/%s", testdir, name);
		remove_file_or_dir(filename);
		fd = creat(filename, FILEMODE);
		if (fd < 0)
			FAILF("create of file %s", filename);

		if (filesize > 0) {
			if (lseek(fd, filesize - 1, SEEK_SET) == -1) {
				close(fd);
				FAILF("lseek of file %s", filename);
			}
			if (write(fd, &zero, 1) == -1) {
				close(fd);
				FAILF("write of file %s", filename);
			}
		}
		if (filesize > 0 && fill) {
			if (lseek(fd, 0, SEEK_SET) == -1) {
				close(fd);
				FAILF("lseek of file %s", filename);
			}
			memset(buf, c, 1024);
			while (left > 0) {
				rc = write(fd, buf, MAX(left, 8192));
				if (rc < 0) {
					close(fd);
					FAILF("write of file %s", filename);
				}
				left -= rc;
			}
		}
		if (close(fd) == -1)
			FAILF("close of file %s", filename);
	}
}

void check_stat(char *filename, struct stat *state, struct stat *old_state)
{
	if (stat(filename, state) == -1)
		FAILF("stat of file %s", filename);

	if (memcmp(state, old_state, sizeof(struct stat)) != 0) {
		errno = 0;
		FAILF(LP_STAT_FMT, LP_STAT_ARGS);
	}
}

void remove_file(char *name)
{
	char filename[MAX_FILENAME_LEN];

	/* Process 0 remove the file(s) */
	if (rank == 0) {
		sprintf(filename, "%s/%s", testdir, name);
		if (unlink(filename) == -1)
			FAILF("unlink of file %s", filename);
	}
}

void fill_stride(char *buf, int buf_size, long long rank, long long _off)
{
	char *p = buf;
	long long off, data[2];
	int cp, left = buf_size;

	data[0] = rank;
	off = _off;
	while (left > 0) {
		data[1] = off;
		cp = left > sizeof(data) ? sizeof(data) : left;
		memcpy(p, data, cp);
		off += cp;
		p += cp;
		left -= cp;
	}
}
