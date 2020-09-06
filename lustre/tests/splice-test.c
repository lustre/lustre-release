// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 RedHat Inc.  All Rights Reserved.
 * Author: Andreas Gruenbacher <agruenba@redhat.com>
 *
 * Make sure that reading and writing to a pipe via splice.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#define SECTOR_SIZE (sysconf(_SC_PAGESIZE))
#define BUFFER_SIZE (150 * SECTOR_SIZE)

void read_from_pipe(int fd, const char *filename, size_t size)
{
	char buffer[SECTOR_SIZE];
	size_t sz;
	ssize_t ret;

	while (size) {
		sz = size;
		if (sz > sizeof(buffer))
			sz = sizeof(buffer);
		ret = read(fd, buffer, sz);
		if (ret < 0)
			err(1, "read: %s", filename);
		if (ret == 0) {
			fprintf(stderr, "read: %s: unexpected EOF\n", filename);
			exit(1);
		}
		size -= sz;
	}
}

void do_splice1(int fd, const char *filename, size_t size)
{
	bool retried = false;
	int pipefd[2];

	if (pipe(pipefd) == -1)
		err(1, "pipe");
	while (size) {
		ssize_t spliced;

		spliced = splice(fd, NULL, pipefd[1], NULL, size, SPLICE_F_MOVE);
		if (spliced == -1) {
			if (errno == EAGAIN && !retried) {
				retried = true;
				fprintf(stderr, "retrying splice\n");
				sleep(1);
				continue;
			}
			err(1, "splice");
		}
		read_from_pipe(pipefd[0], filename, spliced);
		size -= spliced;
	}
	close(pipefd[0]);
	close(pipefd[1]);
}

void do_splice2(int fd, const char *filename, size_t size)
{
	bool retried = false;
	int pipefd[2];
	int pid;

	if (pipe(pipefd) == -1)
		err(1, "pipe");

	pid = fork();
	if (pid == 0) {
		close(pipefd[1]);
		read_from_pipe(pipefd[0], filename, size);
		exit(0);
	} else {
		close(pipefd[0]);
		while (size) {
			ssize_t spliced;

			spliced = splice(fd, NULL, pipefd[1], NULL, size, SPLICE_F_MOVE);
			if (spliced == -1) {
				if (errno == EAGAIN && !retried) {
					retried = true;
					fprintf(stderr, "retrying splice\n");
					sleep(1);
					continue;
				}
				err(1, "splice");
			}
			size -= spliced;
		}
		close(pipefd[1]);
		waitpid(pid, NULL, 0);
	}
}

void usage(const char *argv0)
{
	fprintf(stderr, "USAGE: %s [-rd] {filename}\n", basename(argv0));
	exit(2);
}

int main(int argc, char *argv[])
{
	void (*do_splice)(int fd, const char *filename, size_t size);
	const char *filename;
	char *buffer;
	int opt, open_flags, fd;
	ssize_t ret;

	do_splice = do_splice1;
	open_flags = O_CREAT | O_TRUNC | O_RDWR | O_DIRECT;

	while ((opt = getopt(argc, argv, "rd")) != -1) {
		switch (opt) {
		case 'r':
			do_splice = do_splice2;
			break;
		case 'd':
			open_flags &= ~O_DIRECT;
			break;
		default:  /* '?' */
			usage(argv[0]);
		}
	}

	if (optind >= argc)
		usage(argv[0]);
	filename = argv[optind];

	printf("%s reader %s O_DIRECT\n",
		   do_splice == do_splice1 ? "sequential" : "concurrent",
		   (open_flags & O_DIRECT) ? "with" : "without");

	buffer = aligned_alloc(SECTOR_SIZE, BUFFER_SIZE);
	if (buffer == NULL)
		err(1, "aligned_alloc");

	fd = open(filename, open_flags, 0666);
	if (fd == -1)
		err(1, "open: %s", filename);

	memset(buffer, 'x', BUFFER_SIZE);
	ret = write(fd, buffer, BUFFER_SIZE);
	if (ret < 0)
		err(1, "write: %s", filename);
	if (ret != BUFFER_SIZE) {
		fprintf(stderr, "%s: short write\n", filename);
		exit(1);
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret != 0)
		err(1, "lseek: %s", filename);

	do_splice(fd, filename, BUFFER_SIZE);

	if (unlink(filename) == -1)
		err(1, "unlink: %s", filename);

	return 0;
}
