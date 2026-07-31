// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, DDN.
 */
/*
 * Test program for swapping a single stripe between two files by OST FID.
 *
 * Usage: swap_single_stripe <file1> <fid1> <file2> <fid2>
 *   fid format: seq:oid:ver (brackets optional) e.g. 0x240000400:0x105:0x0
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <lustre/lustreapi.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <file1> <fid1> <file2> <fid2>\n"
		"  fid format: seq:oid:ver (brackets optional)\n", prog);
	exit(1);
}

#define SWAP_MAX_RETRIES 10

int main(int argc, char *argv[])
{
	struct lu_fid fid1, fid2;
	const char *file1, *file2;
	__u64 dv1, dv2;
	int fd1, fd2, rc;
	int retries;

	if (argc != 5)
		usage(argv[0]);

	file1 = argv[1];
	file2 = argv[3];
	if (llapi_fid_parse(argv[2], &fid1, NULL) ||
	    llapi_fid_parse(argv[4], &fid2, NULL)) {
		fprintf(stderr, "Error: invalid FID\n");
		return 1;
	}

	fd1 = open(file1, O_RDWR);
	if (fd1 < 0) {
		fprintf(stderr, "Error: cannot open %s: %s\n",
			file1, strerror(errno));
		return 1;
	}
	fd2 = open(file2, O_RDWR);
	if (fd2 < 0) {
		fprintf(stderr, "Error: cannot open %s: %s\n",
			file2, strerror(errno));
		close(fd1);
		return 1;
	}

	printf("Swapping " DFID " in %s with " DFID " in %s\n",
	       PFID(&fid1), file1, PFID(&fid2), file2);

	/*
	 * API always checks data versions; capture them just before the
	 * swap. The version can be bumped by unrelated activity (e.g. a
	 * glimpse/attribute revalidation) between the read here and the
	 * check done internally by the swap ioctl, so retry a few times
	 * on -EAGAIN instead of treating it as a hard failure.
	 */
	for (retries = 0; retries < SWAP_MAX_RETRIES; retries++) {
		rc = llapi_get_data_version(fd1, &dv1, 0);
		if (rc < 0) {
			fprintf(stderr, "Error: data version %s: %s\n",
				file1, strerror(-rc));
			close(fd2);
			close(fd1);
			return 1;
		}
		rc = llapi_get_data_version(fd2, &dv2, 0);
		if (rc < 0) {
			fprintf(stderr, "Error: data version %s: %s\n",
				file2, strerror(-rc));
			close(fd2);
			close(fd1);
			return 1;
		}

		rc = llapi_fswap_layout_fids(fd1, fd2, &fid1, &fid2, dv1, dv2,
					      0);
		if (rc != -EAGAIN)
			break;

		usleep(100000);
	}
	if (rc < 0) {
		fprintf(stderr, "Error: swap failed: %s\n", strerror(-rc));
		close(fd2);
		close(fd1);
		return 1;
	}

	printf("Stripe swap successful\n");
	close(fd2);
	close(fd1);
	return 0;
}
