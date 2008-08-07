/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>

/* Beware when setting FSROOT that I've not made any attempts to avoid buffer
 * overruns below--this is a test program, it's a static buffer. */
#define FSROOT "/mnt"
#define OBD_ITERATIONS 10000

int main (int argc, char * argv[])
{
	int fd, rc, err = -1;
	struct stat stat_buf;

	if (argc < 2) {
		printf("syntax: %s command\n", argv[0]);
		printf("Where command is one of \"setup\" or \"create\".\n");
		exit(1);
	}

	if (!strcmp(argv[1], "setup")) {
		printf("This is silly.\n");
	} else if (!strcmp(argv[1], "create")) {
		int i, iter;

		if (argc < 3) {
			printf("create requires a nonzero argument.\n");
			exit(1);
		}

		iter = atoi(argv[2]);

		if (iter < 1) {
			printf("create requires a nonzero argument.\n");
			exit(1);
		}
		printf("creating %d files...\n", iter);

		for (i = 0; i < iter; i++) {
			fd = creat(FSROOT "/foo123", S_IRWXU);
			close(fd);
			unlink(FSROOT "/foo123");
		}
	} else {
		printf("Invalid command, run with no arguments for help.\n");
	}

	return 0;
}
