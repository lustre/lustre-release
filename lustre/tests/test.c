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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <asm/statfs.h>
#include <unistd.h>
#include <linux/lustre_idl.h>

#define LOOP_DEVICE "/dev/loop0"
#define OBD_DEVICE "/dev/obd"

int main (int argc, char * argv[])
{
	int fd, rc, err = -1;
	struct stat stat_buf;
	struct statfs stfs;


	if (argc < 2) {
		printf("syntax: %s command [argument]\n", argv[0]);
		printf("Where command is one of \"setup\", \"create\", \"destroy\", or \"sync\".\n");
		exit(1);
	}
	if (stat(LOOP_DEVICE, &stat_buf)) {
		printf("Couldn't stat(" LOOP_DEVICE ").\n");
		exit(1);
	}
	printf("Device: %u\n", (unsigned int) stat_buf.st_rdev);

	fd = open (OBD_DEVICE, O_RDONLY);
	if (fd == -1) {
		printf("Couldn't open " OBD_DEVICE ".\n");
		exit(1);
	}

	if (!strcmp(argv[1], "setup")) {
		rc = ioctl(fd, OBD_IOC_SETUP, &stat_buf.st_rdev);
		fprintf(stderr, "rc = %d, errno = %d\n", rc, errno);
	} else if (!strcmp(argv[1], "create")) {
		int iter, i;

		if (argc < 3) {
			printf("create requires a nonzero argument.\n");
			exit(1);
		}

		iter = atoi(argv[2]);
		if (iter < 1) {
			printf("create requires a nonzero argument.\n");
			exit(1);
		}
		printf("creating %d objects...\n", iter);

		for (i = 0; i < iter; i++) {
			if ((rc = ioctl(fd, OBD_IOC_CREATE, &err))) {
				fprintf(stderr, "Error; aborting.\n");
				break;
			}
			if ((rc = ioctl(fd, OBD_IOC_DESTROY, &err))) {
				fprintf(stderr, "Error; aborting.\n");
				break;
			}
		}
		fprintf(stderr, "rc = %d, errno = %d, err = %d\n",
			rc, errno, err);
	} else if (!strcmp(argv[1], "sync")) {
		rc = ioctl(fd, OBD_IOC_SYNC, &err);
		fprintf(stderr, "rc = %d, errno = %d, err = %d\n",
			rc, errno, err);
	} else if (!strcmp(argv[1], "destroy")) {
		int ino;

		if (argc < 3) {
			printf("destroy requires a nonzero inode number.\n");
			exit(1);
		}

		ino = atoi(argv[2]);
		if (ino < 1) {
			printf("destroy requires a nonzero inode number.\n");
			exit(1);
		}

		rc = ioctl(fd, OBD_IOC_DESTROY, &ino);
		fprintf(stderr, "rc = %d, errno = %d\n", rc, errno);
	} else {
		printf("Invalid command, run with no arguments for help.\n");
	}
	close(fd);

	return 0;
}
