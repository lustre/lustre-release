/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Utility functions for calling ioctls.
 */

#ifndef _LIBCFS_IOCTL_H_
#define _LIBCFS_IOCTL_H_

#include <stdbool.h>
#include <linux/types.h>

/* Sparse annotation. */
#define __user

#include <linux/lnet/libcfs_ioctl.h>

#define LIBCFS_IOC_INIT(data)					\
do {								\
	memset(&(data), 0, sizeof(data));			\
	(data).ioc_hdr.ioc_version = LNET_IOCTL_VERSION;	\
	(data).ioc_hdr.ioc_len = sizeof(data);			\
} while (0)

#define LIBCFS_IOC_INIT_V2(data, hdr)			\
do {							\
	memset(&(data), 0, sizeof(data));		\
	(data).hdr.ioc_version = LNET_IOCTL_VERSION2;	\
	(data).hdr.ioc_len = sizeof(data);		\
} while (0)

/* FIXME - rename these to libcfs_ */
int libcfs_ioctl_pack(struct libcfs_ioctl_data *data, char **pbuf, int max);
void libcfs_ioctl_unpack(struct libcfs_ioctl_data *data, char *pbuf);
int register_ioc_dev(int dev_id, const char *dev_name);
void unregister_ioc_dev(int dev_id);
int l_ioctl(int dev_id, unsigned int opc, void *buf);
#endif
