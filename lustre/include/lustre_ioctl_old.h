/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2023, DataDirect Networks Storage, all rights reserved.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Compatibility for deprecated ioctls that should no longer be used by tools.
 */

#ifndef __LUSTRE_IOCTL_OLD_H
#define __LUSTRE_IOCTL_OLD_H

#include <linux/lnet/libcfs_ioctl.h> /* for IOCTL_LIBCFS_TYPE */

/* ioctl command is deprecated after release v1.v2 */
#define case_OBD_IOC_DEPRECATED(cmd, dev, v1, v2)			\
	case cmd:							\
	if (LUSTRE_VERSION_CODE > OBD_OCD_VERSION(v1, v2, 53, 0)) {	\
		static bool printed;					\
		obd_ioctl_msg(__FILE__, __func__, __LINE__,		\
			      printed ? D_IOCTL : D_WARNING, dev, cmd,	\
			      "deprecated " #cmd " usage", 0);		\
		printed = true;						\
	}

#define case_OBD_IOC_DEPRECATED_FT(cmd, dev, v1, v2)			\
	case_OBD_IOC_DEPRECATED(cmd, dev, v1, v2)			\
	fallthrough

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 19, 53, 0)
#define OBD_GET_VERSION		_IOWR('f', 144, OBD_IOC_DATA_TYPE) /*< 2.8.55 */
#endif

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 99, 53, 0)
/* for binary compatibility until 3.0, no more compiling into tools */
#define OBD_IOC_GETNAME_OLD	_IOWR('f', 131, OBD_IOC_DATA_TYPE) /*< 2.14.52*/

#define IOC_LIBCFS_GET_NI	_IOWR('e', 50, IOCTL_LIBCFS_TYPE)  /*< 2.15.53*/
#define IOC_LIBCFS_PING		_IOWR('e', 61, IOCTL_LIBCFS_TYPE)  /*< 2.15.53*/

#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 19, 53, 0)
#define OBD_IOC_BARRIER		_IOWR('g', 5, OBD_IOC_DATA_TYPE)   /*< 2.16.55*/
#define IOC_OSC_SET_ACTIVE	_IOWR('h', 21, void *)		   /*< 2.16.55*/
#endif

#endif /* OBD_OCD_VERSION(2, 99, 53, 0) */

/* We don't need *_ALLOW() macros for most ioctls, just a few using a bad
 * _IOC_TYPE value (i.e. not 'f') so that "early exit" type checks work.
 */
#define OBD_IOC_CMD_LATE(cmd, name) unlikely(cmd == name)
#define OBD_IOC_CMD_GONE(cmd, name) (false)

#ifdef OBD_IOC_BARRIER
#define OBD_IOC_BARRIER_ALLOW(cmd) OBD_IOC_CMD_LATE(cmd, OBD_IOC_BARRIER)
#else
#define OBD_IOC_BARRIER_ALLOW(cmd) OBD_IOC_CMD_GONE(cmd)
#endif
#ifdef IOC_OSC_SET_ACTIVE
#define IOC_OSC_SET_ACTIVE_ALLOW(cmd) OBD_IOC_CMD_LATE(cmd, IOC_OSC_SET_ACTIVE)
#else
#define IOC_OSC_SET_ACTIVE_ALLOW(cmd) OBD_IOC_CMD_GONE(cmd)
#endif

#endif /* __LUSTRE_IOCTL_OLD_H */
