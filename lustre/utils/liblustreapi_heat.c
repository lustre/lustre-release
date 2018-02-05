/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright (c) 2018, DataDirect Networks Inc, all rights reserved.
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
 * lustre/utils/liblustreapi_heat.c
 *
 * lustreapi library for heat
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
