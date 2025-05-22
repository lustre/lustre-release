// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2018, DataDirect Networks Inc, all rights reserved.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustreapi library for file activity (heat)
 *
 * Author: Li Xi <lixi@ddn.com>
 */

#include <lustre/lustreapi.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <libcfs/util/ioctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ioctl.h>
#include "lustreapi_internal.h"

/*
 * Get heat of a file
 *
 * \param fd       File to get heat.
 * \param heat     Buffer to save heat.
 *
 * \retval 0 on success.
 * \retval -errno on failure.
 */
int llapi_heat_get(int fd, struct lu_heat *heat)
{
	int rc;

	rc = ioctl(fd, LL_IOC_HEAT_GET, heat);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, -errno, "cannot get heat");
		return -errno;
	}
	return 0;
}

/*
 * Set heat of a file
 *
 * \param fd       File to get heat.
 * \param heat     Buffer to save heat.
 *
 * \retval 0 on success.
 * \retval -errno on failure.
 */
int llapi_heat_set(int fd, __u64 flags)
{
	int rc;

	rc = ioctl(fd, LL_IOC_HEAT_SET, &flags);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, -errno, "cannot set heat flags");
		return -errno;
	}
	return 0;
}
