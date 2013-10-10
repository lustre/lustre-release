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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

#define LNET_MINOR 240

int libcfs_ioctl_data_adjust(struct libcfs_ioctl_data *data)
{
	if (libcfs_ioctl_is_invalid(data)) {
		CERROR("LNET: ioctl not correctly formatted\n");
		RETURN(-EINVAL);
	}

	if (data->ioc_inllen1 != 0)
		data->ioc_inlbuf1 = &data->ioc_bulk[0];

	if (data->ioc_inllen2 != 0)
		data->ioc_inlbuf2 = &data->ioc_bulk[0] +
			cfs_size_round(data->ioc_inllen1);

	RETURN(0);
}

int libcfs_ioctl_getdata_len(const struct libcfs_ioctl_hdr __user *arg,
			     __u32 *len)
{
	struct libcfs_ioctl_hdr hdr;
	ENTRY;

	if (copy_from_user(&hdr, arg, sizeof(hdr)))
		RETURN(-EFAULT);

	if (hdr.ioc_version != LIBCFS_IOCTL_VERSION &&
	    hdr.ioc_version != LIBCFS_IOCTL_VERSION2) {
		CERROR("LNET: version mismatch expected %#x, got %#x\n",
		       LIBCFS_IOCTL_VERSION, hdr.ioc_version);
		RETURN(-EINVAL);
	}

	*len = hdr.ioc_len;

	RETURN(0);
}

int libcfs_ioctl_getdata(struct libcfs_ioctl_hdr *buf, __u32 buf_len,
			 const void __user *arg)
{
	ENTRY;

	if (copy_from_user(buf, arg, buf_len))
		RETURN(-EINVAL);

	RETURN(0);
}

int libcfs_ioctl_popdata(void *arg, void *data, int size)
{
	if (copy_to_user((char *)arg, data, size))
		return -EFAULT;
	return 0;
}

extern struct cfs_psdev_ops          libcfs_psdev_ops;

static int
libcfs_psdev_open(struct inode * inode, struct file * file)
{
	struct libcfs_device_userstate **pdu = NULL;
	int    rc = 0;

	if (!inode)
		return (-EINVAL);
	pdu = (struct libcfs_device_userstate **)&file->private_data;
	if (libcfs_psdev_ops.p_open != NULL)
		rc = libcfs_psdev_ops.p_open(0, (void *)pdu);
	else
		return (-EPERM);
	return rc;
}

/* called when closing /dev/device */
static int
libcfs_psdev_release(struct inode * inode, struct file * file)
{
	struct libcfs_device_userstate *pdu;
	int    rc = 0;

	if (!inode)
		return (-EINVAL);
	pdu = file->private_data;
	if (libcfs_psdev_ops.p_close != NULL)
		rc = libcfs_psdev_ops.p_close(0, (void *)pdu);
	else
		rc = -EPERM;
	return rc;
}

static long libcfs_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	struct cfs_psdev_file	 pfile;
	int    rc = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (_IOC_TYPE(cmd) != IOC_LIBCFS_TYPE ||
	    _IOC_NR(cmd) < IOC_LIBCFS_MIN_NR ||
	    _IOC_NR(cmd) > IOC_LIBCFS_MAX_NR) {
		CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
		       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
		return (-EINVAL);
	}

	/* Handle platform-dependent IOC requests */
	switch (cmd) {
	case IOC_LIBCFS_PANIC:
		if (!cfs_capable(CFS_CAP_SYS_BOOT))
			return (-EPERM);
		panic("debugctl-invoked panic");
		return (0);
	case IOC_LIBCFS_MEMHOG:
		if (!cfs_capable(CFS_CAP_SYS_ADMIN))
			return -EPERM;
		/* go thought */
	}

	pfile.off = 0;
	pfile.private_data = file->private_data;
	if (libcfs_psdev_ops.p_ioctl != NULL)
		rc = libcfs_psdev_ops.p_ioctl(&pfile, cmd, (void *)arg);
	else
		rc = -EPERM;
	return (rc);
}

static struct file_operations libcfs_fops = {
	unlocked_ioctl: libcfs_ioctl,
	open :          libcfs_psdev_open,
	release :       libcfs_psdev_release
};

struct miscdevice libcfs_dev = {
	LNET_MINOR,
	"lnet",
	&libcfs_fops
};
