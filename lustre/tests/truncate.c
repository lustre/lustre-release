// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
	const char *path;
	off_t length;
	int rc;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s PATH LENGTH\n",
			program_invocation_short_name);
		exit(EXIT_FAILURE);
	}

	path = argv[1];
	length = strtoull(argv[2], NULL, 0);

	rc = truncate(path, length);
	if (rc < 0) {
		fprintf(stderr, "%s: cannot truncate '%s' to length %lld: %s\n",
			program_invocation_short_name, path, (long long)length,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
