/* GPL HEADER START
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
 * Copyright (C) 2014, DataDirect Networks, Inc.
 * Author: Swapnil Pimpale <spimpale@ddn.com>
 */

/*
 * This test case tests the following scenarios
 * 1) Preallocate: try to fallocate memory blocks and write to it
 *	i) Non-sparse file
 *		- DEFAULT MODE
 *	ii) Sparse file
 *		- create a hole in a file and preallocate using both the
 *		modes
 * Rest of mode flags is not supported currenlty
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <mntent.h>
#include <lustre/lustreapi.h>

#define WRITE_BLOCKS	10
#define HOLE_BLOCKS	10

/* global */
loff_t	blksize;

void usage(char *prog)
{
	fprintf(stderr, "usage: %s <filepath>\n", prog);
	fprintf(stderr, "filepath: absolute pathname of Lustre file\n");
	exit(1);
}

int write_data_to_file(int fd)
{
	char buf[blksize + 1];
	int rc, i, j;

	for (i = 0; i < WRITE_BLOCKS; i++) {
		for (j = 0; j < blksize; j++)
			buf[j] = 'X';
		buf[j] = '\0';
		rc = write(fd, buf, blksize);
		if (rc < 0) {
			fprintf(stderr, "write failed error %s\n",
				strerror(errno));
			return errno;
		}
	}
	return 0;
}

int get_stat(int fd, struct stat *st)
{
	int rc = 0;

	bzero(st, sizeof(struct stat));
	if (fstat(fd, st)) {
		fprintf(stderr, "stat file error: %s\n", strerror(errno));
		rc = errno;
	}
	return rc;
}

int __do_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
	int rc;

	rc = fallocate(fd, mode, offset, len);
	if (rc != 0) {
		fprintf(stderr, "fallocate failed, error %s, mode %d, "
			"offset %llu, len %llu\n", strerror(errno), mode,
			(unsigned long long)offset, (unsigned long long)len);
		rc = errno;
	}

	return rc;
}

int post_fallocate_checks(int fd, int mode, loff_t offset, loff_t len,
			  loff_t expected_new_size)
{
	struct stat st;
	int rc = 0;

	/* check the new size */
	rc = get_stat(fd, &st);
	if (rc != 0)
		goto out;

	if (st.st_size != expected_new_size) {
		fprintf(stderr, "fallocate succeeded but size reported "
			"is wrong\n");
		fprintf(stderr, "mode %d, offset %llu, len %llu, "
			"new_size %llu, expected_new_size %llu\n", mode,
			(unsigned long long)offset, (unsigned long long)len,
			(unsigned long long)st.st_size,
			(unsigned long long)expected_new_size);
		rc = -1;
	}
out:
	return rc;
}

int create_hole(int fd)
{
	int rc;

	rc = write_data_to_file(fd);
	if (rc != 0)
		goto out;

	lseek(fd, HOLE_BLOCKS * blksize, SEEK_CUR);

	rc = write_data_to_file(fd);
	if (rc != 0)
		return rc;
out:
	return rc;
}

int do_fallocate(int fd, int mode, loff_t offset, loff_t expected_new_size)
{
	int rc;
	loff_t len;

	len = blksize;
	rc = __do_fallocate(fd, mode, offset, len);
	if (rc != 0)
		goto out;

	rc = post_fallocate_checks(fd, mode, offset, len, expected_new_size);
	if (rc != 0) {
		fprintf(stderr, "post_fallocate_checks failed for mode %d\n",
			mode);
		goto out;
	}
out:
	return rc;

}

int test_prealloc_nonsparse(int fd)
{
	int rc, mode;
	loff_t offset, expected_new_size;
	struct stat st;

	lseek(fd, 0, SEEK_SET);
	rc = write_data_to_file(fd);
	if (rc != 0)
		goto out;

	rc = get_stat(fd, &st);
	if (rc != 0)
		goto out;

	/* test default mode */
	mode = 0;
	offset = lseek(fd, 0, SEEK_END);
	expected_new_size = WRITE_BLOCKS * blksize + blksize;
	rc = do_fallocate(fd, mode, offset, expected_new_size);
out:
	return rc;
}

int test_prealloc_sparse(int fd)
{
	int rc, mode;
	loff_t offset, expected_new_size;
	struct stat st;

	rc = ftruncate(fd, 0);
	if (rc != 0) {
		fprintf(stderr, "ftruncate error %s\n", strerror(errno));
		rc = errno;
		goto out;
	}

	lseek(fd, 0, SEEK_SET);
	rc = create_hole(fd);
	if (rc != 0)
		goto out;

	rc = get_stat(fd, &st);
	if (rc != 0)
		goto out;

	/* test default mode */
	mode = 0;
	offset = lseek(fd, (WRITE_BLOCKS + HOLE_BLOCKS / 2) * blksize,
		       SEEK_SET);
	expected_new_size = (2 * WRITE_BLOCKS + HOLE_BLOCKS) * blksize;
	rc = do_fallocate(fd, mode, offset, expected_new_size);
out:
	return rc;
}

int main(int argc, char *argv[])
{
	char *fname, *mount_point = NULL;
	int rc = -EINVAL, fd;
	struct stat st;
	struct mntent *ent;
	FILE *mntpt;

	if (argc != 2)
		usage(argv[0]);

	fname = argv[1];
	if (fname[0] != '/') {
		fprintf(stderr, "Need absolute path of the file\n");
		goto out;
	}

	fd = open(fname, O_RDWR | O_CREAT, 0700);
	if (fd < 0) {
		fprintf(stderr, "open file %s error: %s\n",
			fname, strerror(errno));
		rc = errno;
		goto out;
	}

	mntpt = setmntent("/etc/mtab", "r");
	if (mntpt == NULL) {
		fprintf(stderr, "setmntent error: %s\n",
			strerror(errno));
		rc = errno;
		goto out_open;
	}

	while (NULL != (ent = getmntent(mntpt))) {
		if (llapi_is_lustre_mnttype(ent->mnt_fsname) == 0) {
			mount_point = ent->mnt_dir;
			break;
		}
	}
	endmntent(mntpt);

	if (mount_point == NULL) {
		fprintf(stderr, "file not on lustre filesystem?\n");
		goto out_open;
	}

	rc = get_stat(fd, &st);
	if (rc != 0)
		goto out_open;
	blksize = st.st_blksize;

	rc = test_prealloc_nonsparse(fd);
	if (rc != 0)
		goto out_open;

	rc = test_prealloc_sparse(fd);
	if (rc != 0)
		goto out_open;

out_open:
	close(fd);
out:
	return rc;
}
