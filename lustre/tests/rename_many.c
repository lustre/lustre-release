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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define PATH_LENGTH 35
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <getopt.h>

struct names {
	char from[PATH_LENGTH];
	char to[PATH_LENGTH];
} *names;

unsigned int loop_count = 500;
int file_count = 1000;
int seed;
int loops;
int stop;
long start;

int opt_exit_on_err;
int opt_verbose;
int opt_create_only;
int opt_rename_only;
int creat_errors;
int rename_errors;
int unlink_errors;

void usage(const char *progname)
{
	fprintf(stderr, "usage: %s [-n numfiles] [-s seed] [-v] [-x] [dir]\n"
		"\t-c: only do the create step of first loop\n"
		"\t-f: number of files to create/rename/unlink per loop\n"
		"\t-n: number of test loops (0 to run forever)\n"
		"\t-r: only do the rename step of first loop\n"
		"\t-s: starting seed (equals loop number by default)\n"
		"\t-v: verbose\n"
		"\t-x: don't exit on error\n", progname);
}

void handler(int sig) {
	static long last_time;
	long now = time(0);

	signal(SIGINT, handler);
	signal(SIGALRM, handler);
	printf("%6lds %8d iterations %d/%d/%d errors",
	       now - start, loops, creat_errors, rename_errors, unlink_errors);
	if (sig != 0)
		printf(" - use SIGQUIT (^\\) or ^C^C to kill\n");
	else
		printf("\n");

	if (sig == SIGQUIT)
		stop = 1;
	else if (sig == SIGINT) {
		if (now - last_time < 2)
			stop = 1;
		last_time = now;
	}
	alarm(60);
}

extern char *optarg;
extern int optind;

int main(int argc, char *argv[])
{
	unsigned long n;
	char msg[100], *end = NULL;
	int h1, h2;
	int i, c;

	while ((c = getopt(argc, argv, "cf:n:rs:vx")) != EOF) {
		switch(c) {
		case 'c':
			++opt_create_only;
			break;
		case 'f':
			i = strtoul(optarg, &end, 0);
			if (i && end != NULL && *end == '\0') {
				file_count = i;
			} else {
				fprintf(stderr, "bad file count '%s'\n",optarg);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'n':
			i = strtoul(optarg, &end, 0);
			if (i && end != NULL && *end == '\0') {
				loop_count = i;
			} else {
				fprintf(stderr, "bad loop count '%s'\n",optarg);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'r':
			++opt_rename_only;
			break;
		case 's':
			i = strtoul(optarg, &end, 0);
			if (end && *end == '\0') {
				seed = i;
			} else {
				seed = random();
				fprintf(stderr, "using random seed %u\n", seed);
			}
			break;
		case 'v':
			++opt_verbose;
			break;
		case 'x':
			++opt_exit_on_err;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	names = malloc(sizeof(struct names) * file_count);
	if (names == NULL) {
		perror("calloc");
		return(1);
	}

	h2 = sprintf(msg, "%x", file_count); /* just to figure length */
	h1 = (PATH_LENGTH - h2 - 2) / 4;

	n = (1ULL << h1 * 4) - 1;

	//printf("h1 = %d, h2 = %d n = %lu\n", h1, h2, n);

	start = time(0);

	signal(SIGQUIT, handler);
	signal(SIGINT, handler);
	signal(SIGALRM, handler);
	signal(SIGUSR1, handler);
	alarm(60);

	if (argc > optind + 1) {
		fprintf(stderr, "too many extra args %d\n", argc - optind);
		usage(argv[0]);
		return 1;
	} else if (argv[optind] != NULL) {
		if (chdir(argv[optind]) < 0) {
			snprintf(msg, sizeof(msg),
				 "chdir '%s'\n", argv[optind]);
			perror(msg);
			return 2;
		}
	}

	while (!stop && loop_count != 0 && loops < loop_count) {
		int j,k,l,m;

		srand(seed + loops);
		if (mkdir("tmp", S_IRWXU) == -1) {
			perror("mkdir tmp");
			return(1);
		}
		if (chdir("tmp") == -1) {
			perror("chdir tmp");
			return(1);
		}

		for (i = 0; i < file_count ; i++) {
			j = random() & n;
			k = random() & n;
			l = random() & n;
			m = random() & n;
			sprintf(names[i].from, "%0*x%0*x%0*x%0*x0%0*x",
				h1, j, h1, k, h1, l, h1, m, h2, i);
			sprintf(names[i].to, "%0*x%0*x%0*x%0*x1%0*x",
				h1, j, h1, k, h1, l, h1, m, h2, i);

		}

		for (i = 0; i < file_count; i++) {
			if (mknod(names[i].from, S_IFREG | S_IRWXU, 0) == -1) {
				sprintf(msg, "loop %d.%d: creat %s",
					loops, i, names[i].from);
				perror(msg);
				creat_errors++;
				if (!opt_exit_on_err)
					return 4;
			}
		}

		if (opt_create_only)
			return 0;

		for (i = 0; i < file_count; i++) {
			if (rename(names[i].from, names[i].to) == -1) {
				sprintf(msg, "loop %d.%d: rename %s to %s",
					loops, i, names[i].from, names[i].to);
				perror(msg);
				rename_errors++;
				if (!opt_exit_on_err)
					return 4;
			}
		}

		if (opt_rename_only)
			return 0;

		for (i = 0; i < file_count; i++) {
			if (unlink(names[i].to) == -1) {
				sprintf(msg, "loop %d.%d: unlink %s",
					loops, i, names[i].to);
				perror(msg);
				unlink_errors++;
				if (!opt_exit_on_err)
					return 4;
			}
		}

		if (chdir("..") == -1) {
			perror("chdir ..");
			return(1);
		}

		if (rmdir("tmp") == -1) {
			if (chdir("tmp") == -1) {
				perror("chdir tmp 2");
				return(1);
			}
			for (i = 0; i < file_count; i++) {
				if (unlink(names[i].from) != -1) {
					fprintf(stderr, "loop %d.%d: "
						"unexpected file %s\n",
						loops, i, names[i].to);
					unlink_errors++;
					if (!opt_exit_on_err)
						return 4;
				}
			}
			if (chdir("..") == -1) {
				perror("chdir .. 2");
				return(1);
			}
			if (rmdir("tmp") == -1) {
				perror("rmdir tmp");
				return(1);
			}
		}

		loops++;
		if (opt_verbose)
			handler(0);
	}

	if (!opt_verbose)
		handler(0);
	return(0);
}
