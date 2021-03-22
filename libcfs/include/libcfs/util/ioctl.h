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
 * Copyright (c) 2014, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/include/libcfs/util/ioctl.h
 *
 * Utility functions for calling ioctls.
 *
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
	(data).ioc_hdr.ioc_version = LIBCFS_IOCTL_VERSION;	\
	(data).ioc_hdr.ioc_len = sizeof(data);			\
} while (0)

#define LIBCFS_IOC_INIT_V2(data, hdr)			\
do {							\
	memset(&(data), 0, sizeof(data));		\
	(data).hdr.ioc_version = LIBCFS_IOCTL_VERSION2;	\
	(data).hdr.ioc_len = sizeof(data);		\
} while (0)

/* FIXME - rename these to libcfs_ */
int libcfs_ioctl_pack(struct libcfs_ioctl_data *data, char **pbuf, int max);
void libcfs_ioctl_unpack(struct libcfs_ioctl_data *data, char *pbuf);
int register_ioc_dev(int dev_id, const char *dev_name);
void unregister_ioc_dev(int dev_id);
int l_ioctl(int dev_id, unsigned int opc, void *buf);
#endif
