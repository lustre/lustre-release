/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
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
