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
 * Copyright (C) 2013, DataDirect Networks, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Author: Swapnil Pimpale <spimpale@ddn.com>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <mntent.h>
#include <linux/unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <lustre/lustre_user.h>

#define MAX_HANDLE_SZ 128

#if !defined(HAVE_FHANDLE_GLIBC_SUPPORT) && defined(HAVE_FHANDLE_SYSCALLS)
/* Because the kernel supports this functions doesn't mean that glibc does.
 * Just in case we define what we need */
struct file_handle {
	__u32 handle_bytes;
	int handle_type;
	/* file identifier */
	unsigned char f_handle[0];
};

#if defined(_ASM_X86_UNISTD_64_H)

#ifndef __NR_name_to_handle_at
#define __NR_name_to_handle_at 303
#endif

#ifndef __NR_open_by_handle_at
#define __NR_open_by_handle_at 304
#endif

#elif defined(_ASM_X86_UNISTD_32_H)

#ifndef __NR_name_to_handle_at
#define __NR_name_to_handle_at 341
#endif

#ifndef __NR_open_by_handle_at
#define __NR_open_by_handle_at 342
#endif

#else

#ifndef __NR_name_to_handle_at
#define __NR_name_to_handle_at 264
#endif

#ifndef __NR_open_by_handle_at
#define __NR_open_by_handle_at 265
#endif


#endif

static inline int
name_to_handle_at(int mnt_fd, const char *filename, struct file_handle *fh,
		  int *mnt_id, int flags)
{
	return syscall(__NR_name_to_handle_at, mnt_fd, filename, fh,
		       &mnt_id, flags);
}

static inline int
open_by_handle_at(int mnt_fd, struct file_handle *fh, int mode)
{
	return syscall(__NR_open_by_handle_at, mnt_fd, fh, mode);
}
#endif

void usage(char *prog)
{
	fprintf(stderr, "usage: %s <filepath>\n",
		prog);
	fprintf(stderr, "the absolute path of a test file on a "
		"lustre file system is needed.\n");
	exit(1);
}

int main(int argc, char **argv)
{
#ifdef HAVE_FHANDLE_SYSCALLS
	char *filename, *file, *mount_point = NULL, *readbuf = NULL;
	int ret, rc = -EINVAL, mnt_id, mnt_fd, fd1, fd2, i, len, offset;
	struct file_handle *fh = NULL;
	int file_size, mtime, ctime;
	struct lu_fid *parent, *fid;
	struct mntent *ent;
	struct stat st;
	__ino_t inode;
	FILE *mntpt;

	if (argc != 2)
		usage(argv[0]);

	file = argv[1];
	if (file[0] != '/') {
		fprintf(stderr, "Need the absolete path of the file\n");
		goto out;
	}

	fd1 = open(file, O_RDONLY);
	if (fd1 < 0) {
		fprintf(stderr, "open file %s error: %s\n",
			file, strerror(errno));
		rc = errno;
		goto out;
	}

	/* Get file stats using fd1 from traditional open */
	bzero(&st, sizeof(struct stat));
	rc = fstat(fd1, &st);
	if (rc < 0) {
		fprintf(stderr, "fstat(%s) error: %s\n", file,
			strerror(errno));
		rc = errno;
		goto out_fd1;
	}

	inode = st.st_ino;
	mtime = st.st_mtime;
	ctime = st.st_ctime;
	file_size = st.st_size;

	/* Now for the setup to use fhandles */
	mntpt = setmntent("/etc/mtab", "r");
	if (mntpt == NULL) {
		fprintf(stderr, "setmntent error: %s\n",
			strerror(errno));
		rc = errno;
		goto out_fd1;
	}

	while (NULL != (ent = getmntent(mntpt))) {
		if ((strncmp(file, ent->mnt_dir, strlen(ent->mnt_dir)) == 0) &&
		    (strcmp(ent->mnt_type, "lustre") == 0)) {
			mount_point = ent->mnt_dir;
			break;
		}
	}
	endmntent(mntpt);

	if (mount_point == NULL) {
		fprintf(stderr, "file is not located on a lustre file "
			"system?\n");
		goto out_fd1;
	}

	filename = rindex(file, '/') + 1;

	/* Open mount point directory */
	mnt_fd = open(mount_point, O_DIRECTORY);
	if (mnt_fd < 0) {
		fprintf(stderr, "open(%s) error: %s\n)", mount_point,
			strerror(errno));
		rc = errno;
		goto out_fd1;
	}

	/* Allocate memory for file handle */
	fh = malloc(sizeof(struct file_handle) + MAX_HANDLE_SZ);
	if (!fh) {
		fprintf(stderr, "malloc(%d) error: %s\n", MAX_HANDLE_SZ,
			strerror(errno));
		rc = errno;
		goto out_mnt_fd;
	}
	fh->handle_bytes = MAX_HANDLE_SZ;

	/* Convert name to handle */
	ret = name_to_handle_at(mnt_fd, filename, fh, &mnt_id,
				AT_SYMLINK_FOLLOW);
	if (ret) {
		fprintf(stderr, "name_by_handle_at(%s) error: %s\n", filename,
			strerror(errno));
		rc = errno;
		goto out_f_handle;
	}

	/* Print out the contents of the file handle */
	fprintf(stdout, "fh_bytes: %u\nfh_type: %d\nfh_data: ",
		fh->handle_bytes, fh->handle_type);
	for (i = 0; i < fh->handle_bytes; i++)
		fprintf(stdout, "%02x ", fh->f_handle[i]);
	fprintf(stdout, "\n");

	/* Lustre stores both the parents FID and the file FID
	 * in the f_handle. */
	parent = (struct lu_fid *)(fh->f_handle + 16);
	fid = (struct lu_fid *)fh->f_handle;
	fprintf(stdout, "file's parent FID is "DFID"\n", PFID(parent));
	fprintf(stdout, "file FID is "DFID"\n", PFID(fid));

	/* Open the file handle */
	fd2 = open_by_handle_at(mnt_fd, fh, O_RDONLY);
	if (fd2 < 0) {
		fprintf(stderr, "open_by_handle_at(%s) error: %s\n", filename,
			strerror(errno));
		rc = errno;
		goto out_f_handle;
	}

	/* Get file size */
	bzero(&st, sizeof(struct stat));
	rc = fstat(fd2, &st);
	if (rc < 0) {
		fprintf(stderr, "fstat(%s) error: %s\n", filename,
			strerror(errno));
		rc = errno;
		goto out_fd2;
	}

	if (ctime != st.st_ctime || file_size != st.st_size ||
	    inode != st.st_ino || mtime != st.st_mtime) {
		fprintf(stderr, "stat data does not match between fopen "
			"and fhandle case\n");
		goto out_fd2;
	}

	if (st.st_size) {
		len = st.st_blksize;
		readbuf = malloc(len);
		if (readbuf == NULL) {
			fprintf(stderr, "malloc(%d) error: %s\n", len,
				strerror(errno));
			rc = errno;
			goto out_fd2;
		}

		for (offset = 0; offset < st.st_size; offset += len) {
			/* read from the file */
			rc = read(fd2, readbuf, len);
			if (rc < 0) {
				fprintf(stderr, "read(%s) error: %s\n",
					filename, strerror(errno));
				rc = errno;
				goto out_readbuf;
			}
		}
	}

	rc = 0;
	fprintf(stdout, "check_fhandle_syscalls test Passed!\n");

out_readbuf:
	if (readbuf != NULL)
		free(readbuf);
out_fd2:
	close(fd2);
out_f_handle:
	free(fh);
out_mnt_fd:
	close(mnt_fd);
out_fd1:
	close(fd1);
out:
	return rc;
#else /* !HAVE_FHANDLE_SYSCALLS */
	if (argc != 2)
		usage(argv[0]);

	fprintf(stderr, "HAVE_FHANDLE_SYSCALLS not defined\n");
	return 0;
#endif /* HAVE_FHANDLE_SYSCALLS */
}
