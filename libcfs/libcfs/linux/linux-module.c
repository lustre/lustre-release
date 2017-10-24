/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/miscdevice.h>
#include <libcfs/libcfs.h>

static inline size_t libcfs_ioctl_packlen(struct libcfs_ioctl_data *data)
{
	size_t len = sizeof(*data);

	len += (data->ioc_inllen1 + 7) & ~7;
	len += (data->ioc_inllen2 + 7) & ~7;
	return len;
}

static bool libcfs_ioctl_is_invalid(struct libcfs_ioctl_data *data)
{
	if (data->ioc_hdr.ioc_len > BIT(30))
		return true;

	if (data->ioc_inllen1 > BIT(30))
		return true;

	if (data->ioc_inllen2 > BIT(30))
		return true;

	if (data->ioc_inlbuf1 && !data->ioc_inllen1)
		return true;

	if (data->ioc_inlbuf2 && !data->ioc_inllen2)
		return true;

	if (data->ioc_pbuf1 && !data->ioc_plen1)
		return true;

	if (data->ioc_pbuf2 && !data->ioc_plen2)
		return true;

	if (data->ioc_plen1 && !data->ioc_pbuf1)
		return true;

	if (data->ioc_plen2 && !data->ioc_pbuf2)
		return true;

	if (libcfs_ioctl_packlen(data) != data->ioc_hdr.ioc_len)
		return true;

	if (data->ioc_inllen1 &&
	    data->ioc_bulk[((data->ioc_inllen1 + 7) & ~7) +
			     data->ioc_inllen2 - 1] != '\0')
		return true;

	return false;
}

int libcfs_ioctl_data_adjust(struct libcfs_ioctl_data *data)
{
	ENTRY;

	if (libcfs_ioctl_is_invalid(data)) {
		CERROR("libcfs ioctl: parameter not correctly formatted\n");
		RETURN(-EINVAL);
	}

	if (data->ioc_inllen1 != 0)
		data->ioc_inlbuf1 = &data->ioc_bulk[0];

	if (data->ioc_inllen2 != 0)
		data->ioc_inlbuf2 = &data->ioc_bulk[0] +
				    cfs_size_round(data->ioc_inllen1);

	RETURN(0);
}

int libcfs_ioctl_getdata(struct libcfs_ioctl_hdr **hdr_pp,
			 struct libcfs_ioctl_hdr __user *uhdr)
{
	struct libcfs_ioctl_hdr   hdr;
	int err = 0;
	ENTRY;

	if (copy_from_user(&hdr, uhdr, sizeof(hdr)))
		RETURN(-EFAULT);

	if (hdr.ioc_version != LIBCFS_IOCTL_VERSION &&
	    hdr.ioc_version != LIBCFS_IOCTL_VERSION2) {
		CERROR("libcfs ioctl: version mismatch expected %#x, got %#x\n",
		       LIBCFS_IOCTL_VERSION, hdr.ioc_version);
		RETURN(-EINVAL);
	}

	if (hdr.ioc_len < sizeof(struct libcfs_ioctl_hdr)) {
		CERROR("libcfs ioctl: user buffer too small for ioctl\n");
		RETURN(-EINVAL);
	}

	if (hdr.ioc_len > LIBCFS_IOC_DATA_MAX) {
		CERROR("libcfs ioctl: user buffer is too large %d/%d\n",
		       hdr.ioc_len, LIBCFS_IOC_DATA_MAX);
		RETURN(-EINVAL);
	}

	LIBCFS_ALLOC(*hdr_pp, hdr.ioc_len);
	if (*hdr_pp == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(*hdr_pp, uhdr, hdr.ioc_len))
		GOTO(failed, err = -EFAULT);

	RETURN(0);
failed:
	LIBCFS_FREE(*hdr_pp, hdr.ioc_len);
	RETURN(err);
}

static long
libcfs_psdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (_IOC_TYPE(cmd) != IOC_LIBCFS_TYPE ||
	    _IOC_NR(cmd) < IOC_LIBCFS_MIN_NR ||
	    _IOC_NR(cmd) > IOC_LIBCFS_MAX_NR) {
		CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
		       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
		return -EINVAL;
	}

	return libcfs_ioctl(cmd, (void __user *)arg);
}

static struct file_operations libcfs_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = libcfs_psdev_ioctl,
};

struct miscdevice libcfs_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "lnet",
	.fops	= &libcfs_fops
};
