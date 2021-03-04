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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#ifndef S_SHIFT
#define S_SHIFT 12
#endif

int usage(char *prog)
{
	fprintf(stderr, "usage: %s <basename>\n", prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	char name[4096];
	int i;

	if (argc != 2)
		usage(argv[0]);

	umask(0);
	for (i = 0; i <= S_IFMT; i += (1 << S_SHIFT)) {
		struct stat st;
		int mode = i | 0644;
		int rc;

		snprintf(name, sizeof(name), "%s-mknod%07o", argv[1], mode);
		rc = mknod(name, mode, 0x1234);
		switch (i) {
		case 0:
			mode |= S_IFREG;
		case S_IFREG:
		case S_IFCHR: case S_IFBLK:
			if (rc < 0 && getuid() != 0)
				continue;
		case S_IFSOCK: case S_IFIFO:
			if (rc < 0) {
				fprintf(stderr, "%s: ERROR mknod %s: %s\n",
					argv[0], name, strerror(errno));
				exit(10);
			}
			rc = stat(name, &st);
			if (rc < 0) {
				fprintf(stderr, "%s: ERROR stat %s: %s",
					argv[0], name, strerror(errno));
				exit(11);
			}
			if (st.st_mode != mode) {
				fprintf(stderr, "%s: ERROR mode %s: %o != %o",
					argv[0], name, st.st_mode, mode);
				exit(12);
			}
			if (i == S_IFCHR || i == S_IFBLK) {
				if (st.st_rdev != 0x1234) {
					fprintf(stderr, "%s: ERROR rdev %s: "
					        "%llu != 0x1234",
					        argv[0], name,
					        (unsigned long long)st.st_rdev);
					exit(13);
				}
			}
			rc = unlink(name);
			if (rc < 0) {
				fprintf(stderr, "%s: ERROR unlink %s: %s",
					argv[0], name, strerror(errno));
				exit(14);
			}
			break;
		default:
			if (rc == 0) {
				fprintf(stderr, "%s: ERROR: %s created\n",
					argv[0], name);
				exit(15);
			}
		}
	}

	for (i = 0; i <= S_IFMT; i += (1 << S_SHIFT)) {
		struct stat st;
		int mode;
		int fd;
		int rc;

		mode = i | 0644;
		snprintf(name, sizeof(name), "%s-creat%07o", argv[1], mode);
		fd = open(name, O_CREAT|O_RDONLY, mode);
		if (fd < 0) {
			fprintf(stderr, "%s: ERROR creat %s: %s\n",
				argv[0], name, strerror(errno));
			exit(21);
		}
		close(fd);
		rc = stat(name, &st);
		if (rc < 0) {
			fprintf(stderr, "%s: ERROR stat %s: %s",
				argv[0], name, strerror(errno));
			exit(11);
		}
		if (!S_ISREG(st.st_mode & S_IFMT)) {
			fprintf(stderr, "%s: ERROR mode %s: %o != %o",
				argv[0], name, st.st_mode & S_IFMT, S_IFREG);
			exit(12);
		}
		rc = unlink(name);
		if (rc < 0) {
			fprintf(stderr, "%s: ERROR unlink %s: %s\n",
				argv[0], name, strerror(errno));
			exit(20);
		}
	}

	for (i = 0; i <= S_IFMT; i += (1 << S_SHIFT)) {
		struct stat st;
		int rc;

		snprintf(name, sizeof(name), "%s-mkdir%06o", argv[1], i | 0644);
		rc = mkdir(name, i | 0664);
		if (rc < 0) {
			fprintf(stderr, "%s: ERROR mkdir %s: %s\n",
				argv[0], name, strerror(errno));
			exit(30);
		}
		rc = stat(name, &st);
		if (rc < 0) {
			fprintf(stderr, "%s: ERROR stat %s: %s",
				argv[0], name, strerror(errno));
			exit(11);
		}
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "%s: ERROR mode %s: %o != %o",
				argv[0], name, st.st_mode & S_IFMT, S_IFDIR);
			exit(12);
		}
		rc = rmdir(name);
		if (rc < 0) {
			fprintf(stderr, "%s: ERROR rmdir %s: %s\n",
				argv[0], name, strerror(errno));
			exit(31);
		}
	}

	printf("%s: SUCCESS\n", argv[0]);
	return 0;
}
