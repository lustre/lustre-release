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

/* for O_DIRECTORY and O_DIRECT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/lustre/lustre_user.h>

typedef struct flag_mapping {
	const char *string;
	const int  flag;
} FLAG_MAPPING;

FLAG_MAPPING flag_table[] = {
	{"O_RDONLY", O_RDONLY},
	{"O_WRONLY", O_WRONLY},
	{"O_RDWR", O_RDWR},
	{"O_CREAT", O_CREAT},
	{"O_EXCL", O_EXCL},
	{"O_NOCTTY", O_NOCTTY},
	{"O_TRUNC", O_TRUNC},
	{"O_APPEND", O_APPEND},
	{"O_NONBLOCK", O_NONBLOCK},
	{"O_NDELAY", O_NDELAY},
	{"O_SYNC", O_SYNC},
#ifdef O_DIRECT
	{"O_DIRECT", O_DIRECT},
#endif
	{"O_LARGEFILE", O_LARGEFILE},
	{"O_DIRECTORY", O_DIRECTORY},
	{"O_NOFOLLOW", O_NOFOLLOW},
	{"O_LOV_DELAY_CREATE", O_LOV_DELAY_CREATE},
	{"", -1}
};

void Usage_and_abort(void)
{
	fprintf(stderr, "Usage: openfile -f flags [ -m mode ] filename\n");
	fprintf(stderr,
		"e.g. openfile -f O_RDWR:O_CREAT -m 0755 /etc/passwd\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int fd;
	int flags = 0;
	mode_t mode = 0644;
	char *fname = NULL;
	int mode_set = 0;
	int flag_set = 0;
	int c;
	int save_errno = 0;
	int print_usage = 0;
	char *cloned_flags = NULL;

	if (argc == 1)
		Usage_and_abort();

	while ((c = getopt(argc, argv, "f:m:")) != -1) {
		switch (c) {
		case 'f': {
			char *tmp;

			cloned_flags = strdup(optarg);
			if (!cloned_flags) {
				fprintf(stderr, "Insufficient memory.\n");
				save_errno = -1;
				goto out;
			}

			flags = atoi(cloned_flags);
			if (flags > 0) {
				flag_set = 1;
#ifdef DEBUG
				printf("flags = %d\n", flags);
#endif
				break;
			}

			flags = 0;

			for (tmp = strtok(cloned_flags, ":|"); tmp;
			     tmp = strtok(NULL, ":|")) {
				int i = 0;
#ifdef DEBUG
				printf("flags = %s\n", tmp);
#endif
				flag_set = 1;
				for (i = 0; flag_table[i].flag != -1; i++) {
					if (!strcmp(tmp,
						    flag_table[i].string)) {
						flags |= flag_table[i].flag;
						break;
					}
				}

				if (flag_table[i].flag == -1) {
					fprintf(stderr, "No such flag: %s\n",
						tmp);
					save_errno = -1;
					goto out;
				}
			}
#ifdef DEBUG
			printf("flags = %x\n", flags);
#endif
			break;
		}
		case 'm':
#ifdef DEBUG
			printf("mode = %s\n", optarg);
#endif
			mode = strtol(optarg, NULL, 8);
			mode_set = 1;
#ifdef DEBUG
			printf("mode = %o\n", mode);
#endif
			break;
		default:
			fprintf(stderr, "Bad parameters.\n");
			print_usage = 1;
			goto out;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Bad parameters.\n");
		print_usage = 1;
		goto out;
	}

	fname = argv[optind];

	if (!flag_set) {
		fprintf(stderr, "Missing flag or file-name\n");
		save_errno = -1;
		goto out;
	}

	if (flags & O_CREAT)
		fd = open(fname, flags, mode);
	else
		fd = open(fname, flags);

	save_errno = errno;

	if (fd != -1) {
		printf("Succeed in opening file \"%s\"(flags=%s",
		       fname, cloned_flags);

		if (mode_set)
			printf(", mode=%o", mode);
		printf(")\n");
		close(fd);
	} else {
		fprintf(stderr, "Error in opening file \"%s\"(flags=%s",
			fname, cloned_flags);
		if (mode_set)
			fprintf(stderr, ", mode=%o", mode);
		fprintf(stderr, ") %d: %s\n", save_errno, strerror(save_errno));
	}
out:
	if (cloned_flags)
		free(cloned_flags);
	if (print_usage)
		Usage_and_abort();

	return save_errno;
}
