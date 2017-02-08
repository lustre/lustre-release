/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright (c) 2015, Cray Inc, all rights reserved.
 *
 * Copyright (c) 2016 Intel Corporation.
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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <lustre/lustreapi.h>
#include <libcfs/util/string.h>	/* only needed for compat strlcpy() */
#include <lustre_ver.h>		/* only until LUSTRE_VERSION_CODE is gone */
#include "lustreapi_internal.h"

/*
 * Indicate whether the liblustreapi_init() constructor below has run or not.
 *
 * This can be used by external programs to ensure that the initialization
 * mechanism has actually worked.
 */
bool liblustreapi_initialized;


/**
 * Initialize the library once at startup.
 *
 * Initializes the random number generator (random()). Get
 * data from different places in case one of them fails. This
 * is enough to get reasonably random numbers, but is not
 * strong enough to be used for cryptography.
 */
static __attribute__ ((constructor)) void liblustreapi_init(void)
{
	unsigned int	seed;
	struct timeval	tv;
	int		fd;

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

/**
 * Return the release version for the Lustre modules, e.g. 2.6.92.
 *
 * The "version" file in /proc currently returns only the line:
 * lustre: 2.8.52
 *
 * but in the past it also returned more lines that should be ignored:
 * kernel: patchless_client
 * build: v2_6_92_0-gadb3ee4-2.6.32-431.29.2.el6_lustre.g36cd22b.x86_64
 *
 * \param version[in,out]	buffer to store build version string
 * \param version_size[in]	size of \a version
 *
 * \retval			0 on success
 * \retval			-1 on failure, errno set
 */
int llapi_get_version_string(char *version, unsigned int version_size)
{
	char buffer[4096];
	char *ptr;
	int rc;

	if (version == NULL || version_size == 0) {
		errno = EINVAL;
		return -1;
	}

	rc = get_lustre_param_value(NULL, NULL, FILTER_BY_NONE, buffer,
				    "version", sizeof(buffer));
	if (rc < 0) {
		errno = -rc;
		return -1;
	}

	ptr = strstr(buffer, "lustre:");
	if (ptr) {
		ptr += strlen("lustre:");
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;
	} else {
		ptr = buffer;
	}
	llapi_chomp_string(ptr);

	if (ptr[0] == '\0') {
		errno = ENODATA;
		return -1;
	}

	if (strlcpy(version, ptr, version_size) >= version_size) {
		errno = EOVERFLOW;
		return -1;
	}
	return 0;
}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 4, 53, 0)
/**
 * Return the build version of the Lustre code.
 *
 * The **version argument is pointless, so llapi_get_version_string() is
 * better to use in the future, but give users a few versions to fix * it.
 *
 * \param buffer[in]		temporary buffer to hold version string
 * \param buffer_size[in]	length of the \a buffer
 * \param version[out]		pointer to the start of build version string
 *
 * \retval			0 on success
 * \retval			-ve errno on failure
 */
int llapi_get_version(char *buffer, int buffer_size, char **version)
{
	int rc;
#if LUSTRE_VERSION_CODE > OBD_OCD_VERSION(2, 8, 53, 0)
	static bool printed;
	if (!printed) {
		fprintf(stderr,
			"%s deprecated, use llapi_get_version_string()\n",
			__func__);
		printed = true;
	}
#endif

	rc = llapi_get_version_string(buffer, buffer_size);
	/* keep old return style for this legacy function */
	if (rc == -1)
		rc = -errno;
	else
		*version = buffer;

	return rc;
}
#endif /* LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 4, 53, 0) */
