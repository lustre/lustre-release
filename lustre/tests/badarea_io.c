/*
 * GPL HEADER START
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
	int rc;
	int fd;
	void *volatile buf = (void *)0x4096000;
	void *volatile fd_ptr;

	fd = open(argv[1], O_WRONLY);
	if (fd == -1) {
		perror(argv[1]);
		goto read;
	}

	/* We need rc because Sles11 compiler warns against unchecked
	 * return value of read and write */
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

	rc = write(fd, fd_ptr, 2UL*1024*1024*1024);
	if (rc != 2UL*1024*1024*1024)
		perror("write 2G");

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
