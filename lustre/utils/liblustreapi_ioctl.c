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
 * lustre/utils/liblustreapi_ioctl.c
 *
 * lustreapi library for packing/unpacking obd_ioctl_data structure to
 * send commands to different OBD devices.  Mostly for internal use.
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2023, DataDirect Networks Storage.
 */

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <lustre/lustreapi.h>
#include <libcfs/util/ioctl.h>
#include <linux/lustre/lustre_ioctl.h>
#include <linux/lustre/lustre_ver.h>
#include <lustre_ioctl_old.h>

#include "lustreapi_internal.h"

int llapi_ioctl_pack(struct obd_ioctl_data *data, char **pbuf, int max_len)
{
	struct obd_ioctl_data *overlay;
	char *ptr;

	data->ioc_len = obd_ioctl_packlen(data);
	data->ioc_version = OBD_IOCTL_VERSION;

	if (*pbuf != NULL && data->ioc_len > max_len) {
		llapi_error(LLAPI_MSG_ERROR, -EINVAL,
			    "pbuf = %p, ioc_len = %u, max_len = %d",
			    *pbuf, data->ioc_len, max_len);
		return -EINVAL;
	}

	if (*pbuf == NULL)
		*pbuf = malloc(data->ioc_len);

	if (*pbuf == NULL)
		return -ENOMEM;

	overlay = (struct obd_ioctl_data *)*pbuf;
	memcpy(*pbuf, data, sizeof(*data));

	ptr = overlay->ioc_bulk;
	if (data->ioc_inlbuf1) {
		memcpy(ptr, data->ioc_inlbuf1, data->ioc_inllen1);
		ptr += __ALIGN_KERNEL(data->ioc_inllen1, 8);
	}

	if (data->ioc_inlbuf2) {
		memcpy(ptr, data->ioc_inlbuf2, data->ioc_inllen2);
		ptr += __ALIGN_KERNEL(data->ioc_inllen2, 8);
	}

	if (data->ioc_inlbuf3) {
		memcpy(ptr, data->ioc_inlbuf3, data->ioc_inllen3);
		ptr += __ALIGN_KERNEL(data->ioc_inllen3, 8);
	}

	if (data->ioc_inlbuf4) {
		memcpy(ptr, data->ioc_inlbuf4, data->ioc_inllen4);
		ptr += __ALIGN_KERNEL(data->ioc_inllen4, 8);
	}

	return 0;
}

/**
 * Remap OBD device ioctl cmd to old one in case running with older modules.
 * Replaces callers that use "l_ioctl(OBD_DEV_ID, ...)".
 *
 * \param dev_id	Lustre device number (from 'lctl dl')
 * \param cmd		ioctl command
 * \param buf		ioctl data argument, usually obd_ioctl_data
 */
int llapi_ioctl_dev(int dev_id, unsigned int cmd, void *buf)
{
	unsigned int oldcmd;
	int rc;

	/* common case, ioctl works as expected */
	rc = l_ioctl(dev_id, cmd, buf);
	if (rc >= 0 || errno != ENOTTY)
		return rc;

	switch (cmd) {
	/*
	 * Use #ifdef instead of version check to minimize the places that a
	 * version change might cause a compiler error in the future.
	 *
	 * Version in comment is to allow finding this code for later removal.
	 */
#ifdef OBD_IOC_BARRIER		/* < OBD_OCD_VERSION(2, 19, 53, 0) */
	case OBD_IOC_BARRIER_V2:
		oldcmd = OBD_IOC_BARRIER;
		break;
#endif
#ifdef IOC_OSC_SET_ACTIVE	/* < OBD_OCD_VERSION(2, 19, 53, 0) */
	case OBD_IOC_SET_ACTIVE:
		oldcmd = IOC_OSC_SET_ACTIVE;
		break;
#endif
	default:
		oldcmd = 0;
		break;
	}
	if (oldcmd)
		rc = l_ioctl(dev_id, oldcmd, buf);

	return rc;
}

/**
 * Remap regular file ioctl cmd to old one in case running with older modules.
 * Replaces callers that use "ioctl(fd, ...)".
 *
 * \param fd		open file descriptor
 * \param cmd		ioctl command
 * \param buf		ioctl data argument
 */
int llapi_ioctl(int fd, unsigned int cmd, void *buf)
{
	unsigned int oldcmd;
	int rc;

	if (fd < 0)
		return -EBADF;

	/* common case, ioctl works as expected */
	rc = ioctl(fd, cmd, buf);
	if (rc >= 0 || errno != ENOTTY)
		return rc;

	switch (cmd) {
	/*
	 * Use #ifdef instead of version check to minimize the places that a
	 * version change might cause a compiler error in the future.
	 *
	 * Version in comment is to allow finding this code for later removal.
	 */
#ifdef OBD_IOC_GETNAME_OLD	/* < OBD_OCD_VERSION(2, 18, 53, 0) */
	case OBD_IOC_GETDTNAME:
		oldcmd = OBD_IOC_GETNAME_OLD;
		break;
#endif
	default:
		oldcmd = 0;
		break;
	}
	if (oldcmd)
		rc = ioctl(fd, oldcmd, buf);

	return rc;
}

int llapi_ioctl_unpack(struct obd_ioctl_data *data, char *pbuf, int max_len)
{
	struct obd_ioctl_data *overlay;
	char *ptr;

	if (pbuf == NULL)
		return -EINVAL;

	overlay = (struct obd_ioctl_data *)pbuf;

	/* Preserve the caller's buffer pointers */
	overlay->ioc_inlbuf1 = data->ioc_inlbuf1;
	overlay->ioc_inlbuf2 = data->ioc_inlbuf2;
	overlay->ioc_inlbuf3 = data->ioc_inlbuf3;
	overlay->ioc_inlbuf4 = data->ioc_inlbuf4;

	memcpy(data, pbuf, sizeof(*data));

	ptr = overlay->ioc_bulk;
	if (data->ioc_inlbuf1) {
		memcpy(data->ioc_inlbuf1, ptr, data->ioc_inllen1);
		ptr += __ALIGN_KERNEL(data->ioc_inllen1, 8);
	}

	if (data->ioc_inlbuf2) {
		memcpy(data->ioc_inlbuf2, ptr, data->ioc_inllen2);
		ptr += __ALIGN_KERNEL(data->ioc_inllen2, 8);
	}

	if (data->ioc_inlbuf3) {
		memcpy(data->ioc_inlbuf3, ptr, data->ioc_inllen3);
		ptr += __ALIGN_KERNEL(data->ioc_inllen3, 8);
	}

	if (data->ioc_inlbuf4) {
		memcpy(data->ioc_inlbuf4, ptr, data->ioc_inllen4);
		ptr += __ALIGN_KERNEL(data->ioc_inllen4, 8);
	}

	return 0;
}
