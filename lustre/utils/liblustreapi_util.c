/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright (c) 2015, Cray Inc, all rights reserved.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * LGPL version 2.1 or (at your discretion) any later version.
 * LGPL version 2.1 accompanies this distribution, and is available at
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
 * lustre/utils/liblustreapi_util.c
 *
 * Misc LGPL-licenced utility functions for liblustreapi.
 *
 * Author: Frank Zago <fzago@cray.com>
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

/*
 * Indicate whether the liblustreapi_init() constructor below has run or not.
 *
 * This can be used by external programs to ensure if the initialization
 * mechanism has actually worked.
 */
bool liblustreapi_initialized;


/*
 * Initializes the library
 */
static __attribute__ ((constructor)) void liblustreapi_init(void)
{
	unsigned int	seed;
	struct timeval	tv;
	int		fd;

	/* Initializes the random number generator (random()). Get
	 * data from different places in case one of them fails. This
	 * is enough to get reasonably random numbers, but is not
	 * strong enough to be used for cryptography. */
	seed = syscall(SYS_gettid);

	if (gettimeofday(&tv, NULL) == 0) {
		seed ^= tv.tv_sec;
		seed ^= tv.tv_usec;
	}

	fd = open("/dev/urandom", O_RDONLY | O_NOFOLLOW);
	if (fd >= 0) {
		unsigned int rnumber;
		ssize_t ret;

		ret = read(fd, &rnumber, sizeof(rnumber));
		seed ^= rnumber ^ ret;
		close(fd);
	}

	srandom(seed);
	liblustreapi_initialized = true;
}
