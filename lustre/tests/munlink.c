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
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int rc = 0, i;

	if (argc < 2) {
		printf("Usage %s filename {filename ...}\n", argv[0]);
		return 1;
	}

	for (i = 1; i < argc; i++) {
		rc = unlink(argv[i]);
		if (rc) {
			printf("unlink(%s): %s ", argv[i], strerror(errno));
			rc = access(argv[i], F_OK);
			if (rc && errno == ENOENT)
				printf("(unlinked anyways)\n");
			else if (rc == 0)
				printf("(still exists)\n");
			else
				printf("(%s looking up)\n", strerror(errno));
		}
	}
	return rc;
}
