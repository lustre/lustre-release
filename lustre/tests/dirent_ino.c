// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, DDN Storage Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Print the inode number a directory entry carries, as returned by
 * getdents64(2).
 *
 * stat(2) cannot be used for this: it resolves the name through the VFS,
 * so for ".." at a mount root it answers with the mountpoint's parent
 * rather than with whatever the filesystem put in the directory entry.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct linux_dirent64 {
	unsigned long long	d_ino;
	long long		d_off;
	unsigned short		d_reclen;
	unsigned char		d_type;
	char			d_name[];
};

int main(int argc, char **argv)
{
	char buf[32768];
	const char *dir, *want;
	int fd, rc = 2;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <dir> <name>\n", argv[0]);
		return 1;
	}
	dir = argv[1];
	want = argv[2];

	fd = open(dir, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", dir, strerror(errno));
		return 1;
	}

	for (;;) {
		int nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		int off;

		if (nread < 0) {
			fprintf(stderr, "getdents64(%s): %s\n", dir,
				strerror(errno));
			rc = 1;
			break;
		}
		if (nread == 0)
			break;

		for (off = 0; off < nread;) {
			struct linux_dirent64 *d = (void *)(buf + off);

			if (strcmp(d->d_name, want) == 0) {
				printf("%llu\n", d->d_ino);
				rc = 0;
				goto out;
			}
			off += d->d_reclen;
		}
	}
out:
	close(fd);
	if (rc == 2)
		fprintf(stderr, "%s: no entry '%s'\n", dir, want);
	return rc;
}
