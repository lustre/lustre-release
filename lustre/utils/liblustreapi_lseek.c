/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright (c) 2020, DataDirect Networks Inc, all rights reserved.
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
 * lustre/utils/liblustreapi_lseek.c
 *
 * lustreapi library for lseek-related functionality
 *
 * Author: Mikhail Pershin <mpershin@whamcloud.com>
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef FALLOC_FL_PUNCH_HOLE
#include <linux/falloc.h> /* for RHEL7.3 glibc-headers and earlier */
#endif
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <lustre/lustreapi.h>
#include "lustreapi_internal.h"

/**
 * Check if file has a hole
 *
 * \param fd	file descriptor
 *
 * \retval boolean, true if file has a hole, false otherwise
 */
bool llapi_file_is_sparse(int fd)
{
	off_t file_end, hole_off;

	file_end = lseek(fd, 0, SEEK_END);
	hole_off = lseek(fd, 0, SEEK_HOLE);

	/* Errors are ignored and file is just reported as non-sparse */
	return file_end > 0 && hole_off >= 0 && hole_off < file_end;
}

/**
 * Get the first data segment in given extent.
 *
 * \param src_fd  source file descriptor
 * \param offset  offset to start from
 * \param length  length of data segment found
 *
 * \retval next data offset and length on \p length on success.
 * \retval -errno on failure.
 */
off_t llapi_data_seek(int src_fd, off_t offset, size_t *length)
{
	off_t data_off, hole_off;
	int rc;

	if (offset < 0) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "wrong offset: %jd",
			    offset);
		return rc;
	}

	data_off = lseek(src_fd, offset, SEEK_DATA);
	if (data_off < 0) {
		if (errno != ENXIO) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "failed SEEK_DATA from %jd",
				    offset);
			return rc;
		}
		hole_off = lseek(src_fd, 0, SEEK_END);
		if (data_off > hole_off) /* out of file range */
			return -ENXIO;
		/* no more data in src file, return end of file and zero size
		 * so caller will know there must be hole up to that offset
		 */
		*length = 0;
		return hole_off;
	}

	hole_off = lseek(src_fd, data_off, SEEK_HOLE);
	if (hole_off < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "failed SEEK_HOLE from %jd", data_off);
		return rc;
	}
	*length = hole_off - data_off;
	return data_off;
}

/**
 * Punch hole in a file.
 *
 * \param fd     file descriptor
 * \param start  offset to start from
 * \param length hole length
 *
 * \retval 0 on success.
 * \retval -errno on failure to punch hole
 */
int llapi_hole_punch(int fd, off_t start, size_t length)
{
	int rc;

	rc = fallocate(fd, FALLOC_FL_PUNCH_HOLE, start, length);
	if (rc)
		rc = -errno;
	return rc;
}
