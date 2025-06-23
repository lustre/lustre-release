// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2022, DDN/Whamcloud Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * Probe whether OS supports io_uring.
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

#ifdef __NR_io_uring_register
#include <linux/io_uring.h>

int main(int argc, char **argv)
{
	int rc;

	rc = syscall(__NR_io_uring_register, 0, IORING_UNREGISTER_BUFFERS,
		     NULL, 0);
	if (rc < 0 && errno == ENOSYS) {
		printf("Your kernel does not support io_uring");
		return -ENOSYS;
	}
	return 0;
}
#else
int main(int argc, char **argv)
{
	return -ENOSYS;
}
#endif
