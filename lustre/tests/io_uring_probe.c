/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
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
