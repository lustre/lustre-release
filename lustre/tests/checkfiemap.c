/* GPL HEADER START
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
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please  visit http://www.xyratex.com/contact if you need additional
 * information or have any questions.
 *
 * GPL HEADER END
 */

/*
 * Copyright 2013 Xyratex Technology Limited
 *
 * Author: Artem Blagodarenko <Artem_Blagodarenko@xyratex.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <lustre/lustre_user.h>

#ifndef FS_IOC_FIEMAP
# define FS_IOC_FIEMAP (_IOWR('f', 11, struct fiemap))
#endif

#define ONEMB 1048576

/* This test executes fiemap ioctl and check
 * a) there are no file ranges marked with FIEMAP_EXTENT_UNWRITTEN
 * b) data ranges sizes sum is equal to given in second param */
int check_fiemap(int fd, long long orig_size)
{
	/* This buffer is enougth for 1MB length file */
	union { struct fiemap f; char c[4096]; } fiemap_buf;
	struct fiemap *fiemap = &fiemap_buf.f;
	struct fiemap_extent *fm_extents = &fiemap->fm_extents[0];
	unsigned int count = (sizeof(fiemap_buf) - sizeof(*fiemap)) /
			sizeof(*fm_extents);
	unsigned int i = 0;
	long long file_size = 0;

	memset(&fiemap_buf, 0, sizeof(fiemap_buf));

	fiemap->fm_start = 0;
	fiemap->fm_flags = (FIEMAP_FLAG_SYNC | FIEMAP_FLAG_DEVICE_ORDER);
	fiemap->fm_extent_count = count;
	fiemap->fm_length = FIEMAP_MAX_OFFSET;

	if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0) {
		fprintf(stderr, "error while ioctl %i\n",  errno);
		return -1;
	}

	for (i = 0; i < fiemap->fm_mapped_extents; i++) {
		printf("extent in "
			"offset %lu, length %lu\n"
			"flags: %x\n",
			(unsigned long)fm_extents[i].fe_logical,
			(unsigned long)fm_extents[i].fe_length,
			fm_extents[i].fe_flags);

		if (fm_extents[i].fe_flags & FIEMAP_EXTENT_UNWRITTEN) {
			fprintf(stderr, "Unwritten extent\n");
			return -2;
		} else {
			file_size += fm_extents[i].fe_length;
		}
	}

	printf("No unwritten extents, extents number %u, "
		"file size %lli, original size %lli\n",
		fiemap->fm_mapped_extents,
		file_size, orig_size);
	return file_size != orig_size;
}

int main(int argc, char **argv)
{
	int c;
	struct option long_opts[] = {
		{ .name = "test", .has_arg = no_argument, .val = 't' },
		{ .name = NULL }
	};
	int fd;
	int rc;

	optind = 0;
	while ((c = getopt_long(argc, argv, "t", long_opts, NULL)) != -1) {
		switch (c) {
		case 't':
			return 0;
		default:
			fprintf(stderr, "error: %s: option '%s' unrecognized\n",
				argv[0], argv[optind - 1]);
		return -1;
		}
	}

	if (optind != argc - 2) {
		fprintf(stderr, "Usage: %s <filename> <filesize>\n", argv[0]);
		return -1;
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open %s for reading, error %i",
			argv[optind], errno);
		return -1;
	}

	fprintf(stderr, "fd: %i\n", fd);

	rc = check_fiemap(fd, atoll(argv[optind + 1]));

	if (close(fd) < 0)
		fprintf(stderr, "closing %s, error %i", argv[optind], errno);

	return rc;
}
