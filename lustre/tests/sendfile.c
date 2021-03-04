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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <lustre/lustreapi.h>

#define syserr(str) { perror(str); exit(-1); }

int main(int argc, char *argv[])
{
	char *sfile, *tfile;
	struct stat stbuf;
	int size;
	unsigned long bufsize = 1024 * 1024;
	int infd, outfd;
	int sd[2];
	int rc;
	char *buf;
	char cmd[1024];
	loff_t pos;

	if (argc < 3) {
		fprintf(stderr, "%s <source file> <dest file>\n", argv[0]);
		exit(-1);
	}

	sfile = argv[1];
	tfile = argv[2];

	if (stat(sfile, &stbuf) < 0) {
		if (errno == ENOENT) {
			/* assume doing non-object file testing */
			infd = open(sfile,
				    O_LOV_DELAY_CREATE | O_CREAT | O_RDWR,
				    0644);
			if (infd < 0)
				syserr("open source file:");

			size = random() % (1 * 1024 * 1024) + 1024;
			if (ftruncate(infd, (off_t)size) < 0)
				syserr("truncate file error:");
		} else {
			syserr("stat file: ");
		}
	} else if (S_ISREG(stbuf.st_mode)) {
		size = (int)stbuf.st_size;
		infd = open(sfile, O_RDONLY, 0644);
		if (infd < 0)
			syserr("Open an existing file error:");
	} else {
		fprintf(stderr, "%s is not a regular file\n", sfile);
		exit(-1);
	}

	outfd = open(tfile, O_WRONLY | O_TRUNC | O_CREAT, 0666);
	if (outfd < 0)
		syserr("open dest file:");

	rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sd);
	if (rc < 0)
		syserr("socketpair");

	rc = fcntl(sd[0], F_SETFL, O_NONBLOCK);
	if (rc < 0)
		syserr("fcntl");

	rc = setsockopt(sd[0], SOL_SOCKET, SO_SNDBUF,
			&bufsize, sizeof(bufsize));
	if (rc)
		syserr("setsockopt");

	srandom(time(NULL));

	pos = 0;
	while (size > 0) {
		int rc2;
		size_t seg_size;

		seg_size = random() % bufsize + 1;
		if (seg_size > size)
			seg_size = size;

		while (seg_size) {
			rc = sendfile(sd[0], infd, &pos, seg_size);
			if (rc < 0)
				syserr("sendfile:");

			seg_size -= rc;
			size -= rc;
			if (size == 0)
				close(sd[0]);

			buf = malloc(rc);
			if (read(sd[1], buf, rc) < 0)
				syserr("read from socket:");

			rc2 = write(outfd, buf, rc);
			if (rc2 != rc)
				syserr("write dest file error:");
			free(buf);
		}
	}
	close(sd[1]), close(infd), close(outfd);

	snprintf(cmd, sizeof(cmd), "cmp %s %s\n", sfile, tfile);
	return system(cmd);
}
