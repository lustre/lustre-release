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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char ** argv)
{
	int i, rc = 0, count;
	char dirname[4096];

	if (argc < 3) {
		printf("Usage %s dirnamebase count\n", argv[0]);
		return 1;
	}

	if (strlen(argv[1]) > 4080) {
		printf("name too long\n");
		return 1;
	}

	count = strtoul(argv[2], NULL, 0);

	for (i = 0; i < count; i++) {
		sprintf(dirname, "%s-%d", argv[1], i);
		rc = mkdir(dirname, 0444);
		if (rc) {
			printf("mkdir(%s) error: %s\n",
			       dirname, strerror(errno));
			break;
		}
		if ((i % 10000) == 0)
		    printf(" - created %d (time %ld)\n", i, time(0));
	}
	return rc;
}
