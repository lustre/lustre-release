// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[])
{
	int rc;

	if (argc != 3) {
		fprintf(stderr, "usage: %s from to\n", argv[0]);
		exit(1);
	}

	rc = rename(argv[1], argv[2]);
	if (rc)
		fprintf(stderr, "rename '%s' returned %d: %s\n",
			argv[1], rc, strerror(errno));

	return rc;
}
