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
 * Copyright (c) 2016 Intel Corporation.
 */
#include <errno.h>
#include <stdint.h>

#include <libcfs/util/param.h>
#include <lustre/lustre_user.h>
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
		strncat(pattern, "-*", sizeof(pattern));
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
