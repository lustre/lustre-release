// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	mode_t mode;

	if (argc != 3) {
		printf("usage: %s mode name\n", argv[0]);
		return 1;
	}

	mode = strtoul(argv[1], NULL, 8);
	return chmod(argv[2], mode) ? errno : 0;
}
