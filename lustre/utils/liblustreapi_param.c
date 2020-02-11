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
 * lustre/utils/liblustreapi_param.c
 *
 * This code handles user interaction with the configuration interface
 * to the Lustre file system to fine tune it.
 *
 * Copyright (c) 2016, Intel Corporation.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libcfs/util/param.h>
#include <linux/lustre/lustre_user.h>
#include <lustre/lustreapi.h>
#include "lustreapi_internal.h"

/**
 * return the parameter's path for a specific device type or mountpoint
 *
 * \param param		the results returned to the caller
 * \param obd_type	Lustre OBD device type
 *
 * \param filter	filter combined with the type agrument allow the
 * \param type		caller to limit the scope of the search for the
 *			parameter's path. Typical options are search by
 *			Lustre filesystem name or by the path to a file
 *			or directory in the filesystem.
 *
 * \param param_name	parameter name to fetch
 *
 * Using filter and the type argument we can limit the scope of the
 * search to either the parameter belonging to a specific lustre filesystem
 * (if it exists) or using a given file or directory path located on a
 * mounted Lustre filesystem. The last case it can do is a special search
 * based on exactly what the user passed instead of scanning file paths
 * or specific file systems.
 *
 * If "obd_type" matches a Lustre device then the first matching device
 * (as with "lctl dl", constrained by \param filter and \param type)
 * will be used to provide the return value, otherwise the first such
 * device found will be used.
 *
 * Return 0 for success, with the results stored in \param param.
 * Return -ve value for error.
 */
int
get_lustre_param_path(const char *obd_type, const char *filter,
		      enum param_filter type, const char *param_name,
		      glob_t *param)
{
	char pattern[PATH_MAX];
	int rc = 0;

	if (filter == NULL && type != FILTER_BY_NONE)
		return -EINVAL;

	switch (type) {
	case FILTER_BY_PATH:
		rc = llapi_search_fsname(filter, pattern);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "'%s' is not on a Lustre filesystem",
				    filter);
			return rc;
		}
		if (strlen(pattern) + 3 > sizeof(pattern))
			return -E2BIG;
		strncat(pattern, "-*", sizeof(pattern) - 1);
		break;
	case FILTER_BY_FS_NAME:
		rc = snprintf(pattern, sizeof(pattern) - 1, "%s-*", filter);
		if (rc < 0)
			return rc;
		else if (rc >= sizeof(pattern))
			return -EINVAL;
		rc = 0;
		break;
	case FILTER_BY_EXACT:
		if (strlen(filter) + 1 > sizeof(pattern))
			return -E2BIG;
		strncpy(pattern, filter, sizeof(pattern));
		break;
	case FILTER_BY_NONE:
	default:
		break;
	}

	if (type == FILTER_BY_NONE) {
		if (cfs_get_param_paths(param, "%s", param_name) != 0)
			rc = -errno;
	} else if (param_name != NULL) {
		if (cfs_get_param_paths(param, "%s/%s/%s",
				       obd_type, pattern, param_name) != 0)
			rc = -errno;
	} else {
		if (cfs_get_param_paths(param, "%s/%s",
				       obd_type, pattern) != 0)
			rc = -errno;
	}

	return rc;
}

/**
 * return a parameter of a single line value for a specific device type
 * or mountpoint
 *
 * \param obd_type	Lustre OBD device type
 *
 * \param filter	filter combined with the type agruments allow the
 * \param type		caller to limit the scope of the search for the
 *			parameter's path. Typical options are search by
 *			Lustre filesystem name or by the path to a file
 *			or directory in the filesystem.
 *
 * \param param_name	parameter name to fetch
 * \param value		return buffer for parameter value string
 * \param val_len	size of buffer for return value
 *
 * Using filter and the type argument we can limit the scope of the
 * search to either the parameter belonging to a specific lustre filesystem
 * (if it exists) or using a given file or directory path located on a
 * mounted Lustre filesystem. The last case it can do is a special search
 * based on exactly what the user passed instead of scanning file paths
 * or specific file systems.
 *
 * If "obd_type" matches a Lustre device then the first matching device
 * (as with "lctl dl", constrained by \param filter and \param type)
 * will be used to provide the return value, otherwise the first such
 * device found will be used.
 *
 * Return 0 for success, with a NUL-terminated string in \param value.
 * Return negative errno value for error.
 */
int
get_lustre_param_value(const char *obd_type, const char *filter,
		       enum param_filter type, const char *param_name,
		       char *value, size_t val_len)
{
	glob_t param;
	FILE *fp;
	int rc;

	rc = get_lustre_param_path(obd_type, filter, type, param_name, &param);
	if (rc != 0)
		return -ENOENT;

	fp = fopen(param.gl_pathv[0], "r");
	if (fp == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'",
			    param.gl_pathv[0]);
		goto err;
	}

	if (fgets(value, val_len, fp) == NULL) {
		if (!feof(fp))
			rc = -ferror(fp);
	}
	fclose(fp);
err:
	cfs_free_param_data(&param);

	return rc;
}

int llapi_param_get_paths(const char *pattern, glob_t *paths)
{
	return get_lustre_param_path(NULL, NULL, FILTER_BY_NONE,
				     pattern, paths);
}

/**
 *  Read to the end of the file and count the bytes read.
 */
static int bytes_remaining(int fd, size_t *file_size)
{
	int rc = 0;
	size_t bytes_read = 0;
	long page_size = sysconf(_SC_PAGESIZE);
	char *temp_buf;

	temp_buf = malloc(page_size);
	if (temp_buf == NULL)
		return -ENOMEM;

	while (1) {
		ssize_t count = read(fd, temp_buf, page_size);

		if (count == 0) {
			*file_size = bytes_read;
			break;
		}

		if (count < 0) {
			rc = -errno;
			break;
		}
		bytes_read += count;
	}

	free(temp_buf);
	return rc;
}

/**
 *  Determine the size of a file by reading it.
 */
static int required_size(const char *path, size_t *file_size)
{
	int rc = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	rc = bytes_remaining(fd, file_size);

	close(fd);
	*file_size += 1;
	return rc;
}

static
int copy_file_expandable(const char *path, char **buf, size_t *file_size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	int rc = 0;
	char *temp_buf;
	int fd;
	FILE *fp;

	fp = open_memstream(buf, file_size);
	if (fp == NULL) {
		rc = -errno;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		goto close_stream;
	}

	temp_buf = calloc(1, page_size);
	if (buf == NULL) {
		rc = -ENOMEM;
		goto close_file;
	}

	while (1) {
		ssize_t count = read(fd, temp_buf, page_size);

		if (count == 0)
			break;
		if (count < 0) {
			rc = -errno;
			break;
		}

		if (fwrite(temp_buf, 1, count, fp) != count) {
			rc = -errno;
			break;
		}
	}

	free(temp_buf);
close_file:
	close(fd);
close_stream:
	fclose(fp);
out:
	/* If rc != 0 and *buf != NULL, the caller may retry.
	 * This would likely result in copy_file_fixed() being called
	 * on accident, and a likely memory error.
	 */
	if (rc != 0) {
		free(*buf);
		*buf = NULL;
	}
	return rc;
}

/**
 *  Copy file to a buffer and write the number of bytes copied
 */
static int copy_file_fixed(const char *path, char *buf, size_t *buflen)
{
	int rc = 0;
	size_t bytes_read = 0;
	size_t max_read = *buflen - 1;
	size_t remaining = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	while (bytes_read < max_read) {
		ssize_t count = read(fd,
				     buf + bytes_read,
				     max_read - bytes_read);

		/* read the entire file */
		if (count == 0) {
			*buflen = bytes_read + 1;
			buf[bytes_read] = '\0';
			goto out;
		}

		if (count < 0)
			goto check_size;

		bytes_read += count;
	}

check_size:
	/* need to check size in case error due to buf being too small
	 * for read() or exited loop due to buf being full
	 */
	buf[max_read] = '\0';

	rc = bytes_remaining(fd, &remaining);
	if (rc != 0) {
		rc = -errno;
		goto out;
	}
	*buflen = bytes_read + remaining;

	/* file was not (*buflen - 1) bytes, add 1 for reallocating */
	if (remaining != 0) {
		*buflen += 1;
		rc = -EOVERFLOW;
	}

out:
	close(fd);

	return rc;
}

/**
 * Read the value of the file with location \a path
 * into a buffer.
 *
 * \param path[in]           the location of a parameter file
 * \param buf[in,out]        a pointer to a pointer to a buffer
 * \param buflen[in,out]     the length of a pre-allocated buffer
 *                           when passed in, and either the number
 *                           of bytes written or the suggested
 *                           size of *buf when passed out.
 *
 * There are 3 behaviors based on the value of buf.
 * If buf == NULL, then the buffer size needed to read the file at
 * \a path will be written to \a *buflen.
 * If \a buf != NULL and \a *buf == NULL, the value of *buf will point
 * to a buffer that will be automatically sized to fit the file
 * contents. A NUL byte will be added to the end of the buffer.
 * The value of \a *buflen will be set to the number of bytes written
 * excuding the NUL byte.
 * If \a buf != NULL and \a *buf != NULL, it will be assumed that \a *buf
 * points to a pre-allocated buffer with a capacity of \a *buflen.
 * If there is sufficient space, the file contents and NUL terminating
 * byte will be written to the buffer at .\a *buf.
 * Otherwise, the required size of \a *buflen with be written to \a *buflen.
 *
 * Returns 0 for success with null terminated string in \a *buf.
 * Returns negative errno value on error.
 * For case of \a buf != NULL and \a *buf != NULL, a return value
 * of -EOVERFLOW indicates that it's possible retry with a larger
 * buffer.
 */
int llapi_param_get_value(const char *path, char **buf, size_t *buflen)
{
	int rc = 0;

	if (path == NULL || buflen == NULL)
		rc = -EINVAL;
	else if (buf == NULL)
		rc = required_size(path, buflen);
	/* handle for buffer, but no buffer
	 * create a buffer of the required size
	 */
	else if (*buf == NULL)
		rc = copy_file_expandable(path, buf, buflen);
	/* preallocated buffer given, attempt to copy
	 * file to it, return file size if buffer too small
	 */
	else
		rc = copy_file_fixed(path, *buf, buflen);

	errno = -rc;

	return rc;
}

void llapi_param_paths_free(glob_t *paths)
{
	cfs_free_param_data(paths);
}
