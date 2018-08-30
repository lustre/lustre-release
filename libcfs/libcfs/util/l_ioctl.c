/*
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 *   This file is part of Lustre, https://wiki.whamcloud.com/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define __USE_FILE_OFFSET64

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/types.h>

#include <libcfs/util/ioctl.h>
#include <lnet/lnetctl.h>

struct ioc_dev {
	const char *dev_name;
	int dev_fd;
};

static struct ioc_dev ioc_dev_list[10];

static int
open_ioc_dev(int dev_id)
{
        const char * dev_name;

	if (dev_id < 0 ||
            dev_id >= sizeof(ioc_dev_list) / sizeof(ioc_dev_list[0]))
                return -EINVAL;

        dev_name = ioc_dev_list[dev_id].dev_name;
        if (dev_name == NULL) {
                fprintf(stderr, "unknown device id: %d\n", dev_id);
                return -EINVAL;
        }

        if (ioc_dev_list[dev_id].dev_fd < 0) {
		int fd = open(dev_name, O_RDWR);

                if (fd < 0) {
                        fprintf(stderr, "opening %s failed: %s\n"
                                "hint: the kernel modules may not be loaded\n",
                                dev_name, strerror(errno));
                        return fd;
                }
                ioc_dev_list[dev_id].dev_fd = fd;
        }

        return ioc_dev_list[dev_id].dev_fd;
}


int l_ioctl(int dev_id, unsigned int opc, void *buf)
{
        int fd, rc;

        fd = open_ioc_dev(dev_id);
	if (fd < 0)
                return fd;

	rc = ioctl(fd, opc, buf);

	return rc;
}

/* register a device to send ioctls to.  */
int
register_ioc_dev(int dev_id, const char *dev_name)
{
	if (dev_id < 0 ||
            dev_id >= sizeof(ioc_dev_list) / sizeof(ioc_dev_list[0]))
                return -EINVAL;

        unregister_ioc_dev(dev_id);

        ioc_dev_list[dev_id].dev_name = dev_name;
        ioc_dev_list[dev_id].dev_fd = -1;

        return dev_id;
}

void
unregister_ioc_dev(int dev_id)
{
	if (dev_id < 0 ||
	    dev_id >= sizeof(ioc_dev_list) / sizeof(ioc_dev_list[0]))
		return;

	if (ioc_dev_list[dev_id].dev_name != NULL &&
	    ioc_dev_list[dev_id].dev_fd >= 0)
		close(ioc_dev_list[dev_id].dev_fd);

	ioc_dev_list[dev_id].dev_name = NULL;
	ioc_dev_list[dev_id].dev_fd = -1;
}

static inline size_t libcfs_ioctl_packlen(struct libcfs_ioctl_data *data)
{
	size_t len = sizeof(*data);

	len += (data->ioc_inllen1 + 7) & ~7;
	len += (data->ioc_inllen2 + 7) & ~7;
	return len;
}

int libcfs_ioctl_pack(struct libcfs_ioctl_data *data, char **pbuf,
                                    int max)
{
	char *ptr;
	struct libcfs_ioctl_data *overlay;
	data->ioc_hdr.ioc_len = libcfs_ioctl_packlen(data);
	data->ioc_hdr.ioc_version = LIBCFS_IOCTL_VERSION;

	if (*pbuf != NULL && libcfs_ioctl_packlen(data) > max)
		return 1;
	if (*pbuf == NULL)
		*pbuf = malloc(data->ioc_hdr.ioc_len);
	if (*pbuf == NULL)
		return 1;
	overlay = (struct libcfs_ioctl_data *)*pbuf;
	memcpy(*pbuf, data, sizeof(*data));

	ptr = overlay->ioc_bulk;
	if (data->ioc_inlbuf1 != NULL) {
		memcpy((char *)ptr, (const char *)data->ioc_inlbuf1,
		       data->ioc_inllen1);
		ptr += ((data->ioc_inllen1 + 7) & ~7);
	}
	if (data->ioc_inlbuf2 != NULL) {
		memcpy((char *)ptr, (const char *)data->ioc_inlbuf2,
		       data->ioc_inllen2);
		ptr += ((data->ioc_inllen2 + 7) & ~7);
	}

	return 0;
}

void
libcfs_ioctl_unpack(struct libcfs_ioctl_data *data, char *pbuf)
{
	struct libcfs_ioctl_data *overlay = (struct libcfs_ioctl_data *)pbuf;
	char *ptr;

	/* Preserve the caller's buffer pointers */
	overlay->ioc_inlbuf1 = data->ioc_inlbuf1;
	overlay->ioc_inlbuf2 = data->ioc_inlbuf2;

	memcpy(data, pbuf, sizeof(*data));
	ptr = &overlay->ioc_bulk[0];

	if (data->ioc_inlbuf1 != NULL) {
		memcpy((char *)data->ioc_inlbuf1, (const char *)ptr,
		       data->ioc_inllen1);
		ptr += ((data->ioc_inllen1 + 7) & ~7);
	}
	if (data->ioc_inlbuf2 != NULL) {
		memcpy((char *)data->ioc_inlbuf2, (const char *)ptr,
		       data->ioc_inllen2);
		ptr += ((data->ioc_inllen2 + 7) & ~7);
	}
}
