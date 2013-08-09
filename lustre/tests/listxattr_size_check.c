/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 *
 * Copyright (c) 2013, Intel Corporation.
 *
 * lustre/tests/listxattr_size_check.c
 *
 * Author: Keith Mannthey <keith.mannthey@intel.com>
 */

#include <sys/types.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void usage(char *prog)
{
	printf("Usage: %s <pathname>\n", prog);
}

/* Test the listxattr return value when the buffer is small. */
int main(int argc, char *argv[])
{
	char *path, *buf;
	ssize_t ret_buf, ret_null, error_s;
	int ret = 0;

	if (argc != 2) {
		usage(argv[0]);
		exit(1);
	}

	path = argv[1];

	ret_null = listxattr(path, NULL, 0);
	if (ret_null < 0) {
		fprintf(stderr, "listxattr(%s, NULL, 0) failed "
				"with %i: %s\n", path, errno,
				 strerror(errno));
		ret = errno;
		goto out;
	}

	/* LU-3403 llite: error of listxattr when buffer is small */
	if (ret_null < 2) {
		fprintf(stderr, "listxattr(%s, NULL, 0) returned"
					"a sizes less than 2", path);
		ret = EINVAL;
		goto out;
	}

	error_s = ret_null - 1;
	buf = (char *)malloc(error_s);
	if (buf == NULL) {
		fprintf(stderr, "malloc(%zi) failed with %i: %s\n",
				error_s, errno, strerror(errno));
		ret = errno;
		goto out;
	}

	ret_buf = llistxattr(path, buf, error_s);
	if (ret_buf != -1) {
		fprintf(stderr, "llistxattr(%s, %p, %zi) passed with %zi but "
				"should have failed with -1\n", path, buf,
				 error_s, ret_buf);
		ret = EINVAL;
		goto free;
	}

free:
	free(buf);
out:
	return ret;
}
