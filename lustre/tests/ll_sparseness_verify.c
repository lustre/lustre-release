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
 *
 * lustre/tests/ll_sparseness_verify.c
 *
 * The companion to ll_sparseness_write; walk all the bytes in the file.
 * the bytes at the offsets specified on the command line must be '+', as
 * previously written by ll_sparseness_write.  All other bytes must be 0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#define BUFSIZE (1024 * 1024)

void error(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

int compare_offsets(const void *a, const void *b)
{
	off_t *A = (off_t *)a;
	off_t *B = (off_t *)b;

	return *A - *B;
}

int main(int argc, char **argv)
{
	unsigned int num_offsets, cur_off = 0, i;
	off_t *offsets, pos = 0, end_of_buf = 0;
	char *end, *buf;
	struct stat st;
	ssize_t ret;
	int fd;

	if (argc < 3)
		error("Usage: %s <filename> <offset> [ offset ... ]\n",
		      argv[0]);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		error("couldn't open %s: %s\n", argv[1], strerror(errno));

	buf = malloc(BUFSIZE);
	if (!buf)
		error("can't allocate buffer\n");

	num_offsets = argc - 2;
	offsets = calloc(sizeof(offsets[0]), num_offsets);
	for (i = 0; i < num_offsets; i++) {
		offsets[i] = strtoul(argv[i + 2], &end, 10);
		if (*end)
			error("couldn't parse offset '%s'\n", argv[i + 2]);
	}
	qsort(offsets, num_offsets, sizeof(offsets[0]), compare_offsets);

	if (fstat(fd, &st) < 0)
		error("stat: %s\n", strerror(errno));

	for (i = 0; pos < st.st_size; i++, pos++) {
		if (pos == end_of_buf) {
			ret = read(fd, buf, BUFSIZE);
			if (ret < 0)
				error("read(): %s\n", strerror(errno));
			end_of_buf = pos + ret;
			if (end_of_buf > st.st_size)
				error("read %d bytes past file size?\n",
				      end_of_buf - st.st_size);
			i = 0;
		}

		/* check for 0 when we aren't at a given offset */
		if (cur_off >= num_offsets || pos != offsets[cur_off]) {
			if (buf[i] != 0)
				error("found char 0x%x at pos %lu instead of 0x0\n",
				      buf[i], (long)pos);
			continue;
		}

		/* the command line asks us to check for + at this offset */
		if (buf[i] != '+')
			error("found char 0x%x at pos %lu instead of '.'\n",
			      buf[i], (long)pos);

		/* skip over duplicate offset arguments */
		while (cur_off < num_offsets && offsets[cur_off] == pos)
			cur_off++;
	}
	/* don't bother freeing or closing.. */
	return 0;
}
