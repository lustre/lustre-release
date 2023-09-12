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
#include <pthread.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/lustre/lustre_user.h>

#ifndef FS_IOC_FIEMAP
# define FS_IOC_FIEMAP (_IOWR('f', 11, struct fiemap))
#endif

#define ONEMB 1048576

static inline void print_extent_flags(unsigned int flags) {
	if (!flags)
		return;

	printf("flags (0x%x):", flags);
	if (flags & FIEMAP_EXTENT_LAST)
		printf(" LAST");
	if (flags & FIEMAP_EXTENT_UNKNOWN)
		printf(" UNKNOWN");
	if (flags & FIEMAP_EXTENT_DELALLOC)
		printf(" DELALLOC");
	if (flags & FIEMAP_EXTENT_ENCODED)
		printf(" ENCODED");
	if (flags & FIEMAP_EXTENT_DATA_ENCRYPTED)
		printf(" DATA_ENCRYPTED");
	if (flags & FIEMAP_EXTENT_NOT_ALIGNED)
		printf(" NOT_ALIGNED");
	if (flags & FIEMAP_EXTENT_DATA_INLINE)
		printf(" DATA_INLINE");
	if (flags & FIEMAP_EXTENT_DATA_TAIL)
		printf(" DATA_TAIL");
	if (flags & FIEMAP_EXTENT_UNWRITTEN)
		printf(" UNWRITTEN");
	if (flags & FIEMAP_EXTENT_MERGED)
		printf(" MERGED");
	if (flags & FIEMAP_EXTENT_SHARED)
		printf(" SHARED");
	if (flags & FIEMAP_EXTENT_NET)
		printf(" NET");
	printf("\n");
}


/* This test executes fiemap ioctl and check
 * a) there are no file ranges marked with FIEMAP_EXTENT_UNWRITTEN
 * b) data ranges sizes sum is equal to given in second param */
static int check_fiemap(int fd, long long expected_sum,
			unsigned int *mapped_extents)
{
	/* This buffer is enougth for 1MB length file */
	union { struct fiemap f; char c[4096]; } fiemap_buf;
	struct fiemap *fiemap = &fiemap_buf.f;
	struct fiemap_extent *fm_extents = &fiemap->fm_extents[0];
	unsigned int count = (sizeof(fiemap_buf) - sizeof(*fiemap)) /
			sizeof(*fm_extents);
	unsigned int i = 0;
	long long ext_len_sum = 0;

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
		printf("extent %d in offset %lu, length %lu\n",
			i, (unsigned long)fm_extents[i].fe_logical,
			(unsigned long)fm_extents[i].fe_length);

		print_extent_flags(fm_extents[i].fe_flags);

		if (fm_extents[i].fe_flags & FIEMAP_EXTENT_UNWRITTEN) {
			fprintf(stderr, "Unwritten extent\n");
			return -2;
		} else {
			ext_len_sum += fm_extents[i].fe_length;
		}
	}

	printf("No unwritten extents, extents number %u, sum of lengths %lli, expected sum %lli\n",
		fiemap->fm_mapped_extents,
		ext_len_sum, expected_sum);

	*mapped_extents = fiemap->fm_mapped_extents;
	return ext_len_sum != expected_sum || (expected_sum && !*mapped_extents);
}

/**
 * LU-17110
 * When userspace uses fiemap with fm_extent_count=0, it means that kernelspace
 * should return only the number of extents. So we should always check
 * fm_extent_count before accessing to fm_extents array. Otherwise this could
 * lead to buffer overflow and slab memory corruption.
 */
struct th_args {
	int fd;
	int iter_nbr;
	int expected_mapped;
};

static void *corruption_th(void *args)
{
	int i;
	struct th_args *ta = args;
	struct fiemap fiemap = {
		.fm_start = 0,
		.fm_flags = (FIEMAP_FLAG_SYNC | FIEMAP_FLAG_DEVICE_ORDER),
		.fm_extent_count = 0,
		.fm_length = FIEMAP_MAX_OFFSET };

	for (i = 0; i < ta->iter_nbr; i++) {
		if (ioctl(ta->fd, FS_IOC_FIEMAP, &fiemap) < 0) {
			fprintf(stderr, "error while ioctl: %s\n",
				strerror(errno));
			return (void *) (long long) -errno;
		}
		if (ta->expected_mapped != fiemap.fm_mapped_extents) {
			fprintf(stderr, "mapped extents mismatch: expected=%d, returned=%d\n",
				ta->expected_mapped, fiemap.fm_mapped_extents);
			return (void *) -EINVAL;
		}
	}

	return NULL;
}

int main(int argc, char **argv)
{
	int c;
	struct option long_opts[] = {
		{ .name = "test", .has_arg = no_argument, .val = 't' },
		{ .name = "corruption_test", .has_arg = no_argument, .val = 'c' },
		{ .name = NULL }
	};
	int fd;
	int rc;
	unsigned int mapped_extents = 0;
	bool corruption_test = false;

	optind = 0;
	while ((c = getopt_long(argc, argv, "tc", long_opts, NULL)) != -1) {
		switch (c) {
		case 't':
			return 0;
		case 'c':
			corruption_test = true;
			break;
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

	rc = check_fiemap(fd, atoll(argv[optind + 1]), &mapped_extents);
	if (rc)
		goto close;

	if (corruption_test) {
		pthread_t th[200];
		int i;
		void *rval = NULL;
		struct th_args args = {
			.fd = fd,
			.expected_mapped = mapped_extents,
			.iter_nbr = 500
		};

		for (i = 0; i < 200; i++) {
			rc = pthread_create(&th[i], NULL, corruption_th, &args);
			if (rc)
				goto close;
		}
		for (i = 0; i < 200; i++) {
			rc = pthread_join(th[i], &rval);
			if (rc || rval) {
				rc =  1;
				goto close;
			}
		}
	}
close:
	if (close(fd) < 0)
		fprintf(stderr, "closing %s, error %i", argv[optind], errno);

	return rc;
}
