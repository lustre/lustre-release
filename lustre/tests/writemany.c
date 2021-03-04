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
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>

char cmdname[512];
int o_abort;
int o_quiet;

void usage(char *name)
{
	fprintf(stderr, "usage: %s [opts] <dirname> <seconds> <threads>\n",
		name);
	fprintf(stderr, "  -q quiet\n");
	fprintf(stderr, "  -a abort other children on first err\n");
	exit(1);
}

struct kid_list_t {
	pid_t kid;
	struct kid_list_t *next;
};

struct kid_list_t *head;

int push_kid(pid_t kid)
{
	struct kid_list_t *new;

	new = (struct kid_list_t *)malloc(sizeof(struct kid_list_t));
	if (!new)
		return 1;

	new->kid = kid;
	new->next = head;
	head = new;
	return 0;
}

void kill_kids(void)
{
	while (head) {
		kill(head->kid, SIGTERM);
		head = head->next;
	}
}

static int usr1_received;
void usr1_handler(int unused)
{
	usr1_received = 1;
	kill_kids();
}

int wait_for_threads(int live_threads)
{
	int rc = 0;

	while (live_threads > 0) {
		int status;
		pid_t ret;

		ret = waitpid(0, &status, 0);
		if (ret == 0)
			continue;

		if (ret < 0) {
			fprintf(stderr, "%s: error: wait - %s\n",
				cmdname, strerror(errno));
			if (!rc)
				rc = errno;
		} else {
			/*
			 * This is a hack.  We _should_ be able to use
			 * WIFEXITED(status) to see if there was an
			 * error, but it appears to be broken and it
			 * always returns 1 (OK).  See wait(2).
			 */
			int err = WEXITSTATUS(status);

			if (err)
				fprintf(stderr,
					"%s: error: PID %d had rc=%d\n",
					cmdname, ret, err);
			/* Record first error */
			if (!rc)
				rc = err;

			/* Give up on first error */
			if (rc && o_abort) {
				kill_kids();
				break;
			}

			live_threads--;
		}
	}
	if (!o_quiet)
		printf("%s done, rc = %d\n", cmdname, rc);
	return rc;
}

void print_err(char *op, char *filename, struct timeval *time, int err)
{
	fprintf(stderr, "%s: %d.%.06d error: %s(%s): %s\n",
		cmdname, (int)(time->tv_sec), (int)(time->tv_usec), op,
		filename, strerror(errno));
}

int run_one_child(char *file, int thread, int seconds)
{
	struct timeval start, cur;
	double diff;
	char filename[1024];
	char buf[1024];
	int fd, rc = 0, rand, maxrand, len;
	long nfiles = 0, nbytes = 0;

	if (!o_quiet)
		printf("%s: running thread #%d\n", cmdname, thread);

	srandom(thread);
	/*
	 * Higher thread numbers will produce bigger random files.
	 * Thread 1 will produce only 0-len files.
	 */
	maxrand = 1; rand = thread;
	while (--rand)
		maxrand *= 10;

	gettimeofday(&start, NULL);
	cur = start;

	while (!rc) {
		if (usr1_received)
			break;

		gettimeofday(&cur, NULL);
		if (seconds) {
			if (cur.tv_sec > (start.tv_sec + seconds))
				break;
		}

		snprintf(filename, sizeof(filename), "%s-%d-%ld",
			 file, thread, nfiles);

		fd = open(filename, O_RDWR | O_CREAT, 0666);
		if (fd < 0) {
			print_err("open", filename, &cur, errno);
			rc = errno;
			break;
		}

		sprintf(buf, "%s %010ld %.19s.%012d\n", cmdname,
			nfiles++, ctime(&cur.tv_sec), (int)cur.tv_usec);
		len = strlen(buf);

		rand = random() % maxrand;
		while (rand-- > 0) {
			if (write(fd, buf, len) != len) {
				print_err("write", filename, &cur, errno);
				rc = errno;
				break;
			}
			nbytes += len;
		}

		if (close(fd) < 0) {
			print_err("close", filename, &cur, errno);
			rc = errno;
			break;
		}
		if (unlink(filename) < 0) {
			print_err("unlink", filename, &cur, errno);
			if (errno == ENOENT) {
				printf("Ignoring known bug 6082\n");
			} else {
				rc = errno;
				break;
			}
		}
	}

	diff = difftime(cur.tv_sec, start.tv_sec);
	if (!o_quiet)
		printf("%s: %7ld files, %4ld MB in %.2fs (%7.2f files/s, %5.2f MB/s): rc = %d\n",
		       cmdname, nfiles, nbytes >> 20, diff,
		       diff == 0 ? (double)0 : (double)nfiles / diff,
		       diff == 0 ? (double)0 : (double)nbytes / 1024 / 1024 /
		       diff, rc);

	return rc;
}

int main(int argc, char *argv[])
{
	unsigned long duration;
	int threads = 0;
	char *end;
	char *directory;
	int i = 1, rc = 0;

	snprintf(cmdname, sizeof(cmdname), "%s", argv[0]);

	while ((i < argc) && (argv[i][0] == '-')) {
		switch (argv[i][1]) {
		case 'q':
			o_quiet++;
			break;
		case 'a':
			o_abort++;
			break;
		}
		i++;
	}

	if ((argc - i) < 3)
		usage(argv[0]);

	directory = argv[i];
	duration = strtoul(argv[++i], &end, 0);
	if (*end) {
		fprintf(stderr, "%s: error: bad number of seconds '%s'\n",
			cmdname, argv[i]);
		exit(2);
	}

	threads = strtoul(argv[++i], &end, 0);
	if (*end) {
		fprintf(stderr, "%s: error: bad thread count '%s'\n",
			cmdname, argv[i]);
		exit(2);
	}

	signal(SIGUSR1, usr1_handler);

	for (i = 1; i <= threads; i++) {
		rc = fork();
		if (rc < 0) {
			if (!o_quiet)
				fprintf(stderr, "%s: error: #%d - %s\n",
					cmdname, i, strerror(rc = errno));
			return rc;
		}
		if (rc == 0) {
			/* children */
			snprintf(cmdname, sizeof(cmdname), "%s-%d", argv[0], i);
			return run_one_child(directory, i, duration);
		}
		/* parent */
		rc = push_kid(rc);
		if (rc != 0) {
			kill_kids();
			exit(3);
		}
	}
	/* parent process */
	if (!o_quiet)
		printf("%s will run for %ld minutes\n", cmdname, duration / 60);
	return wait_for_threads(threads);
}
