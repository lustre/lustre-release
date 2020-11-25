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
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/liblustreapi_mirror.c
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <assert.h>
#include <sys/param.h>

#include <libcfs/util/ioctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ioctl.h>

/**
 * Set the mirror id for the opening file pointed by @fd, once the mirror
 * is set successfully, the policy to choose mirrors will be disabed and the
 * following I/O from this file descriptor will be led to this dedicated
 * mirror @id.
 * If @id is zero, it will clear the mirror id setting.
 *
 * \param fd	file descriptor, must be opened with O_DIRECT
 * \param id	mirror id
 *
 * \retval	0 on success.
 * \retval	-errno on failure.
 */
int llapi_mirror_set(int fd, unsigned int id)
{
	struct stat stbuf;
	int rc;

	rc = ioctl(fd, LL_IOC_FLR_SET_MIRROR, id);
	if (rc < 0) {
		rc = -errno;
		return rc;
	}

	if (!id)
		return 0;

	/* in the current implementation, llite doesn't verify if the mirror
	 * id is valid, it has to be verified in an I/O context so the fstat()
	 * call is to verify that the mirror id is correct. */
	rc = fstat(fd, &stbuf);
	if (rc < 0) {
		rc = -errno;

		(void) ioctl(fd, LL_IOC_FLR_SET_MIRROR, 0);
	}

	return rc;
}

/**
 * Clear mirror id setting.
 *
 * \See llapi_mirror_set() for details.
 */
int llapi_mirror_clear(int fd)
{
	return llapi_mirror_set(fd, 0);
}

/**
 * Read data from a specified mirror with @id. This function won't read
 * partial read result; either file end is reached, or number of @count bytes
 * is read, or an error will be returned.
 *
 * \param fd	file descriptor, should be opened with O_DIRECT
 * \param id	mirror id to be read from
 * \param buf	read buffer
 * \param count	number of bytes to be read
 * \param pos	file postion where the read starts
 *
 * \result >= 0	Number of bytes has been read
 * \result < 0	The last seen error
 */
ssize_t llapi_mirror_read(int fd, unsigned int id, void *buf, size_t count,
			  off_t pos)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	int rc;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	while (count > 0) {
		ssize_t bytes_read;

		bytes_read = pread(fd, buf, count, pos);
		if (!bytes_read) /* end of file */
			break;

		if (bytes_read < 0) {
			result = -errno;
			break;
		}

		result += bytes_read;
		pos += bytes_read;
		buf += bytes_read;
		count -= bytes_read;

		if (bytes_read & (page_size - 1)) /* end of file */
			break;
	}

	(void) llapi_mirror_clear(fd);

	return result;
}

ssize_t llapi_mirror_write(int fd, unsigned int id, const void *buf,
			   size_t count, off_t pos)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	int rc;

	if (((unsigned long)buf & (page_size - 1)) || pos & (page_size - 1))
		return -EINVAL;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	while (count > 0) {
		ssize_t bytes_written;

		if (pos & (page_size - 1)) {
			result = -EINVAL;
			break;
		}

		bytes_written = pwrite(fd, buf, count, pos);
		if (bytes_written < 0) {
			result = -errno;
			break;
		}

		result += bytes_written;
		pos += bytes_written;
		buf += bytes_written;
		count -= bytes_written;
	}

	(void) llapi_mirror_clear(fd);

	return result;
}

int llapi_mirror_truncate(int fd, unsigned int id, off_t length)
{
	int rc;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	rc = ftruncate(fd, length);
	if (rc < 0)
		rc = -errno;

	(void) llapi_mirror_clear(fd);

	return rc;
}

int llapi_mirror_punch(int fd, unsigned int id, off_t start, size_t length)
{
	int rc;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	rc = llapi_hole_punch(fd, start, length);
	(void) llapi_mirror_clear(fd);

	return rc;
}

bool llapi_mirror_is_sparse(int fd, unsigned int id)
{
	bool sparse;
	int rc;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return false;

	sparse = llapi_file_is_sparse(fd);
	(void) llapi_mirror_clear(fd);

	return sparse;
}

/**
 * Seek data in a specified mirror with @id. This function looks for the
 * first data segment from given offset and returns its offset and length
 *
 * \param fd	file descriptor, should be opened with O_DIRECT
 * \param id	mirror id to be read from
 * \param pos	position for start data seek from
 * \param size	size of data segment found
 *
 * \result >= 0	Number of bytes has been read
 * \result < 0	The last seen error
 */
off_t llapi_mirror_data_seek(int fd, unsigned int id, off_t pos, size_t *size)
{
	off_t data_off;
	int rc;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	data_off = llapi_data_seek(fd, pos, size);
	(void) llapi_mirror_clear(fd);

	return data_off;
}

/**
 * Copy data contents from source mirror @src to multiple destinations
 * pointed by @dst. The destination array @dst will be altered to store
 * successfully copied mirrors.
 *
 * \param fd	file descriptor, should be opened with O_DIRECT
 * \param src	source mirror id, usually a valid mirror
 * \param dst	an array of destination mirror ids
 * \param count	number of elements in array @dst
 *
 * \result > 0	Number of mirrors successfully copied
 * \result < 0	The last seen error
 */
ssize_t llapi_mirror_copy_many(int fd, __u16 src, __u16 *dst, size_t count)
{
	const size_t buflen = 4 * 1024 * 1024; /* 4M */
	void *buf;
	off_t pos = 0;
	off_t data_end = 0;
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	bool eof = false;
	bool sparse;
	int nr;
	int i;
	int rc;

	if (!count)
		return 0;

	rc = posix_memalign(&buf, page_size, buflen);
	if (rc) /* error code is returned directly */
		return -rc;

	sparse = llapi_mirror_is_sparse(fd, src);

	nr = count;
	if (sparse) {
		/* for sparse src we have to be sure that dst has no
		 * data in src holes, so truncate it first
		 */
		for (i = 0; i < nr; i++) {
			rc = llapi_mirror_truncate(fd, dst[i], pos);
			if (rc < 0) {
				result = rc;
				/* exclude the failed one */
				dst[i] = dst[--nr];
				i--;
				continue;
			}
		}
		if (!nr)
			return result;
	}

	while (!eof) {
		off_t data_off;
		ssize_t bytes_read;
		size_t to_write, to_read;

		if (sparse && pos >= data_end) {
			size_t data_size;

			data_off = llapi_mirror_data_seek(fd, src, pos,
							  &data_size);
			if (data_off < 0) {
				/* Non-fatal, switch to full copy */
				sparse = false;
				continue;
			}
			if (!data_size) {
				/* hole at the end of file, set pos to the
				 * data_off, so truncate block at the end
				 * will set final dst size.
				 */
				pos = data_off;
				break;
			}

			data_end = data_off + data_size;
			/* align by page */
			pos = data_off & ~(page_size - 1);
			data_end = ((data_end - 1) | (page_size - 1)) + 1;
			to_read = MIN(data_end - pos, buflen);
		} else {
			to_read = buflen;
		}

		bytes_read = llapi_mirror_read(fd, src, buf, to_read, pos);
		if (!bytes_read) { /* end of file */
			break;
		} else if (bytes_read < 0) {
			result = bytes_read;
			nr = 0;
			break;
		}

		/* round up to page align to make direct IO happy.
		 * this implies the last segment to write. */
		to_write = ((bytes_read - 1) | (page_size - 1)) + 1;

		for (i = 0; i < nr; i++) {
			ssize_t written;

			written = llapi_mirror_write(fd, dst[i], buf,
						      to_write, pos);
			if (written < 0) {
				result = written;

				/* this mirror is not written succesfully,
				 * get rid of it from the array */
				dst[i] = dst[--nr];
				i--;
				continue;
			}
			assert(written == to_write);
		}
		pos += bytes_read;
		eof = bytes_read < to_read;
	}

	free(buf);

	if (nr > 0) {
		for (i = 0; i < nr; i++) {
			rc = llapi_mirror_truncate(fd, dst[i], pos);
			if (rc < 0) {
				result = rc;

				/* exclude the failed one */
				dst[i] = dst[--nr];
				--i;
				continue;
			}
		}
	}

	return nr > 0 ? nr : result;
}

/**
 * Copy data contents from source mirror @src to target mirror @dst.
 *
 * \param fd	file descriptor, should be opened with O_DIRECT
 * \param src	source mirror id, usually a valid mirror
 * \param dst	mirror id of copy destination
 * \param pos   start file pos
 * \param count	number of bytes to be copied
 *
 * \result > 0	Number of mirrors successfully copied
 * \result < 0	The last seen error
 */
int llapi_mirror_copy(int fd, unsigned int src, unsigned int dst, off_t pos,
		      size_t count)
{
	const size_t buflen = 4 * 1024 * 1024; /* 4M */
	void *buf;
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	int rc;

	if (!count)
		return 0;

	if (pos & (page_size - 1) || !dst)
		return -EINVAL;

	if (count != OBD_OBJECT_EOF && count & (page_size - 1))
		return -EINVAL;

	rc = posix_memalign(&buf, page_size, buflen);
	if (rc) /* error code is returned directly */
		return -rc;

	while (result < count) {
		ssize_t bytes_read, bytes_written;
		size_t to_read, to_write;

		to_read = MIN(buflen, count - result);
		if (src == 0)
			bytes_read = pread(fd, buf, to_read, pos);
		else
			bytes_read = llapi_mirror_read(fd, src, buf, to_read,
							pos);
		if (!bytes_read) { /* end of file */
			break;
		} else if (bytes_read < 0) {
			result = bytes_read;
			break;
		}

		/* round up to page align to make direct IO happy.
		 * this implies the last segment to write. */
		to_write = (bytes_read + page_size - 1) & ~(page_size - 1);

		bytes_written = llapi_mirror_write(fd, dst, buf, to_write,
						    pos);
		if (bytes_written < 0) {
			result = bytes_written;
			break;
		}

		assert(bytes_written == to_write);

		pos += bytes_read;
		result += bytes_read;

		if (bytes_read < to_read) /* short read occurred */
			break;
	}

	free(buf);

	if (result > 0 && pos & (page_size - 1)) {
		rc = llapi_mirror_truncate(fd, dst, pos);
		if (rc < 0)
			result = rc;
	}

	return result;
}
