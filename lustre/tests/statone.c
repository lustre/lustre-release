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
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <lustre/lustreapi.h>

int main(int argc, char **argv)
{
	char parent[4096], *base, *name, *t;
	int fd, offset, rc;

	if (argc != 2) {
		printf("usage: %s filename\n", argv[0]);
		return 1;
	}

	base = argv[1];
	t = strrchr(base, '/');
	if (!t) {
		strcpy(parent, ".");
		offset = -1;
	} else {
		strncpy(parent, base, t - base);
		offset = t - base - 1;
		parent[t - base] = 0;
	}

	fd = open(parent, O_RDONLY);
	if (fd < 0) {
		printf("open(%s) error: %s\n", parent, strerror(errno));
		exit(errno);
	}

	name = base;
	if (offset >= 0)
		name += offset + 2;

	rc = llapi_file_lookup(fd, name);
	if (rc < 0) {
		printf("llapi_file_lookup (%s/%s) error: %s\n", parent,
		       name, strerror(errno));
		exit(errno);
	}

	return 0;
}
