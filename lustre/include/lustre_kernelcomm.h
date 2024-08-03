/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 *
 * Kernel <-> userspace communication routines.
 * The definitions below are used in the kernel and userspace.
 */

#ifndef __LUSTRE_KERNELCOMM_H__
#define __LUSTRE_KERNELCOMM_H__

/* For declarations shared with userspace */
#include <uapi/linux/lustre/lustre_kernelcomm.h>

/**
 * enum lustre_device_attrs	      - Lustre general top-level netlink
 *					attributes that describe lustre
 *					'devices'. These values are used
 *					to piece togther messages for
 *					sending and receiving.
 *
 * @LUSTRE_DEVICE_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LUSTRE_DEVICE_ATTR_HDR:		Netlink group this data is for
 *					(NLA_NUL_STRING)
 * @LUSTRE_DEVICE_ATTR_INDEX:		device number used as an index (NLA_U16)
 * @LUSTRE_DEVICE_ATTR_STATUS:		status of the device (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_CLASS:		class the device belongs to (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_NAME:		name of the device (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_UUID:		UUID of the device (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_REFCOUNT:	refcount of the device (NLA_U32)
 */
enum lustre_device_attrs {
	LUSTRE_DEVICE_ATTR_UNSPEC = 0,

	LUSTRE_DEVICE_ATTR_HDR,
	LUSTRE_DEVICE_ATTR_INDEX,
	LUSTRE_DEVICE_ATTR_STATUS,
	LUSTRE_DEVICE_ATTR_CLASS,
	LUSTRE_DEVICE_ATTR_NAME,
	LUSTRE_DEVICE_ATTR_UUID,
	LUSTRE_DEVICE_ATTR_REFCOUNT,

	__LUSTRE_DEVICE_ATTR_MAX_PLUS_ONE
};

#define LUSTRE_DEVICE_ATTR_MAX (__LUSTRE_DEVICE_ATTR_MAX_PLUS_ONE - 1)

/* prototype for callback function on kuc groups */
typedef int (*libcfs_kkuc_cb_t)(void *data, void *cb_arg);

/* Kernel methods */
int libcfs_kkuc_init(void);
void libcfs_kkuc_fini(void);
int libcfs_kkuc_msg_put(struct file *fp, void *payload);
int libcfs_kkuc_group_put(const struct obd_uuid *uuid, int group, void *data);
int libcfs_kkuc_group_add(struct file *fp, const struct obd_uuid *uuid, int uid,
			  int group, void *data, size_t data_len);
int libcfs_kkuc_group_rem(const struct obd_uuid *uuid, int uid, int group);
int libcfs_kkuc_group_foreach(const struct obd_uuid *uuid, int group,
			      libcfs_kkuc_cb_t cb_func, void *cb_arg);

#endif /* __LUSTRE_KERNELCOMM_H__ */

