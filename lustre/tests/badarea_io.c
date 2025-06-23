// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014, Intel Corporation.
 * Use is subject to license terms.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#undef perror
#define perror(str) ((void)0)

int main(int argc, char **argv)
{
	ssize_t rc;
	int fd;
	void *volatile fd_ptr;
	void *volatile buf = (void *)0x4096000;

	fd = open(argv[1], O_WRONLY);
	if (fd == -1) {
		perror(argv[1]);
		goto read;
	}

	/* We need rc because Sles11 compiler warns against unchecked
	 * return value of read and write
	 */
	rc = write(fd, buf, 5);
	if (rc != 5)
		perror("write badarea (Should have failed)");

	fd_ptr = (void *)&fd;
	rc = write(fd, fd_ptr, 0);
	if (rc != 0)
		perror("write zero bytes");

	rc = write(fd, fd_ptr, 1);
	if (rc != 1)
		perror("write one byte");

	rc = write(fd, fd_ptr, 2UL*1024*1024);
	if (rc != 2UL*1024*1024)
		perror("write 2M");

	rc = write(fd, fd_ptr, 1UL*(1024+512)*1024*1024);
	if (rc != 1UL*(1024+512)*1024*1024)
		perror("write 1.5G");

	rc = write(fd, fd_ptr, -2);
	if (rc != -2)
		perror("write -2");

	close(fd);

read:
	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		return 0;
	rc = read(fd, buf, 5);
	perror("read");

	close(fd);

	/* Tame the compiler spooked about rc assigned, but not used */
	if (!rc)
		return -1; /* Not really important. */

	return 0;
}
