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
 *
 * Copyright (c) 2015 Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void usage(const char *prog)
{
	printf("usage: %s {-o [-k]|-m|-d|-l<tgt>} [-u[<unlinkfmt>]] "
	       "[-t seconds] filenamefmt [[start] count]\n", prog);
	printf("\t-l\tlink files to existing <tgt> file\n"
	       "\t-m\tmknod regular files (don't create OST objects)\n"
	       "\t-o\topen+create files with path and printf format\n"
	       "\t-k\t    keep files open until all files are opened\n"
	       "\t-u\tunlink file/dir (with optional <unlinkfmt>)\n");
	printf("\t-d\tuse directories instead of regular files\n"
	       "\t-t\tstop creating files after <seconds> have elapsed\n");

	exit(EXIT_FAILURE);
}

static char *get_file_name(const char *fmt, long n, int has_fmt_spec)
{
	static char filename[4096];
	int bytes;

	bytes = has_fmt_spec ? snprintf(filename, 4095, fmt, n) :
		snprintf(filename, 4095, "%s%ld", fmt, n);
	if (bytes >= 4095) {
		printf("file name too long\n");
		exit(EXIT_FAILURE);
	}
	return filename;
}

double now(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

int main(int argc, char ** argv)
{
	bool do_open = false, do_keep = false, do_link = false;
	bool do_unlink = false, do_mknod = false, do_mkdir = false;
	char *filename, *progname;
	char *fmt = NULL, *fmt_unlink = NULL, *tgt = NULL;
	char *endp = NULL;
	double start, last_t, end;
	long begin = 0, count = ~0UL >> 1;
	int has_fmt_spec = 0, unlink_has_fmt_spec = 0;
	long i, total, last_i = 0;
	int c, last_fd = -1, stderr_fd;
	int rc = 0;

	/* Handle the deprecated positional last argument "-seconds" */
	if (argc > 1 && argv[argc - 1][0] == '-' &&
	    (end = strtol(argv[argc - 1] + 1, &endp, 0)) && *endp == '\0') {
		fprintf(stderr, "warning: '-runtime' deprecated, "
			"use '-t runtime' instead\n");
		argv[--argc] = NULL;
	} else {
		/* Not '-number', let regular argument parsing handle it. */
		end = ~0U >> 1;
	}

	if ((endp = strrchr(argv[0], '/')) != NULL)
		progname = endp + 1;
	else
		progname = argv[0];

	while ((c = getopt(argc, argv, "dl:kmor::t:u::")) != -1) {
		switch (c) {
		case 'd':
			do_mkdir = true;
			break;
		case 'k':
			do_keep = true;
			break;
		case 'l':
			do_link = true;
			tgt = optarg;
			break;
		case 'm':
			do_mknod = true;
			break;
		case 'o':
			do_open = true;
			break;
		case 't':
			end = strtol(optarg, &endp, 0);
			if (end <= 0.0 || *endp != '\0')
				usage(progname);
			break;
		case 'r':
		case 'u':
			do_unlink = true;
			fmt_unlink = optarg;
			break;
		case '?':
			fprintf(stderr, "Unknown option '%c'\n", optopt);
			usage(progname);
		}
	}

	if (do_open + do_mkdir + do_link + do_mknod > 1 ||
	    do_open + do_mkdir + do_link + do_mknod + do_unlink == 0) {
		fprintf(stderr, "error: only one of -o, -m, -l, -d\n");
		usage(progname);
	}

	if (!do_open && do_keep) {
		fprintf(stderr, "error: can only use -k with -o\n");
		usage(progname);
	}

	switch (argc - optind) {
	case 3:
		begin = strtol(argv[argc - 2], NULL, 0);
	case 2:
		count = strtol(argv[argc - 1], NULL, 0);
	case 1:
		fmt = argv[optind];
		break;
	default:
		usage(progname);
	}

	has_fmt_spec = strchr(fmt, '%') != NULL;
	if (fmt_unlink != NULL)
		unlink_has_fmt_spec = strchr(fmt_unlink, '%') != NULL;

	for (i = 0, start = last_t = now(), end += start;
	     i < count && now() < end; i++, begin++) {
		filename = get_file_name(fmt, begin, has_fmt_spec);
		if (do_open) {
			int fd = open(filename, O_CREAT|O_RDWR, 0644);
			if (fd < 0) {
				printf("open(%s) error: %s\n", filename,
				       strerror(errno));
				rc = errno;
				break;
			}
			if (!do_keep)
				close(fd);
			else if (fd > last_fd)
				last_fd = fd;
		} else if (do_link) {
			rc = link(tgt, filename);
			if (rc) {
				printf("link(%s, %s) error: %s\n",
				       tgt, filename, strerror(errno));
				rc = errno;
				break;
			}
		} else if (do_mkdir) {
			rc = mkdir(filename, 0755);
			if (rc) {
				printf("mkdir(%s) error: %s\n",
				       filename, strerror(errno));
				rc = errno;
				break;
			}
		} else if (do_mknod) {
			rc = mknod(filename, S_IFREG | 0444, 0);
			if (rc) {
				printf("mknod(%s) error: %s\n",
				       filename, strerror(errno));
				rc = errno;
				break;
			}
		}
		if (do_unlink) {
			if (fmt_unlink != NULL)
				filename = get_file_name(fmt_unlink, begin,
							 unlink_has_fmt_spec);

			rc = do_mkdir ? rmdir(filename) : unlink(filename);
			if (rc) {
				printf("unlink(%s) error: %s\n",
				       filename, strerror(errno));
				rc = errno;
				break;
			}
		}

		if ((i != 0 && (i % 10000) == 0) || now() - last_t >= 10.0) {
			double tmp = now();

			printf(" - %s%s %ld (time %.2f total %.2f last %.2f)"
			       "\n",
			       do_open ? do_keep ? "open/keep" : "open/close" :
					do_mkdir ? "mkdir" : do_link ? "link" :
					do_mknod ? "create" : "",
			       do_unlink ? do_mkdir ? "/rmdir" : "/unlink" : "",
			       i, tmp, tmp - start,
			       (i - last_i) / (tmp - last_t));
			last_t = tmp;
			last_i = i;
		}
	}
	last_t = now();
	total = i;
	printf("total: %ld %s%s in %.2f seconds: %.2f ops/second\n", total,
	       do_open ? do_keep ? "open/keep" : "open/close" :
			do_mkdir ? "mkdir" : do_link ? "link" :
					     do_mknod ? "create" : "",
	       do_unlink ? do_mkdir ? "/rmdir" : "/unlink" : "",
	       last_t - start, ((double)total / (last_t - start)));

	if (!do_keep)
		return rc;

	stderr_fd = fileno(stderr);
	start = last_t;
	/* Assume fd is allocated in order, doing extra closes is not harmful */
	for (i = 0; i < total && last_fd > stderr_fd; i++, --last_fd) {
		close(last_fd);

		if ((i != 0 && (i % 10000) == 0) || now() - last_t >= 10.0) {
			double tmp = now();

			printf(" - closed %ld (time %.2f total %.2f last %.2f)"
			       "\n", i, tmp, tmp - start,
			       (i - last_i) / (tmp - last_t));
			last_t = tmp;
			last_i = i;
		}
	}
	last_t = now();

	printf("total: %ld close in %.2f seconds: %.2f close/second\n",
	       total, last_t - start, ((double)total / (last_t - start)));
	return rc;
}
