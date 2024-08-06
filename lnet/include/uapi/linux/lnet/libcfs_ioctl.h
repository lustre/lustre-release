/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * Low-level ioctl data structures. Kernel ioctl functions declared here,
 * and user space functions are in libcfs/util/ioctl.h.
 */

#ifndef __UAPI_LIBCFS_IOCTL_H__
#define __UAPI_LIBCFS_IOCTL_H__

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * sparse kernel source annotations
 */
#ifndef __user
#define __user
#endif

#define LNET_IOCTL_VERSION 0x0001000a
#define LNET_IOCTL_VERSION2 0x0001000b

struct libcfs_ioctl_hdr {
	__u32 ioc_len;
	__u32 ioc_version;
};

/** max size to copy from userspace */
#define LIBCFS_IOC_DATA_MAX	(128 * 1024)

struct libcfs_ioctl_data {
	struct libcfs_ioctl_hdr ioc_hdr;

	__u64 ioc_nid;
	__u64 ioc_u64[1];

	__u32 ioc_flags;
	__u32 ioc_count;
	__u32 ioc_net;
	__u32 ioc_u32[7];

	__u32 ioc_inllen1;
	char *ioc_inlbuf1;
	__u32 ioc_inllen2;
	char *ioc_inlbuf2;

	__u32 ioc_plen1; /* buffers in userspace */
	void __user *ioc_pbuf1;
	__u32 ioc_plen2; /* buffers in userspace */
	void __user *ioc_pbuf2;

	char ioc_bulk[];
};

#define IOCTL_LIBCFS_TYPE		  long

#define IOC_LIBCFS_TYPE				      ('e')
#define IOC_LIBCFS_MIN_NR			      30
/* libcfs ioctls */
/* XXX: all of these ioctl definitions are broken, the first parameter
 * should be IOCTL_LIBCFS_TYPE and the last parameter is the struct size.
 */
#define IOC_LIBCFS_CLEAR_DEBUG             _IOWR('e', 31, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_MARK_DEBUG              _IOWR('e', 32, IOCTL_LIBCFS_TYPE)
/* lnet ioctls */
#define IOC_LIBCFS_GET_NI		   _IOWR('e', 50, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_FAIL_NID		   _IOWR('e', 51, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_NOTIFY_ROUTER	   _IOWR('e', 55, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_UNCONFIGURE		   _IOWR('e', 56, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_LNET_DIST		   _IOWR('e', 58, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_CONFIGURE		   _IOWR('e', 59, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_TESTPROTOCOMPAT	   _IOWR('e', 60, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_PING_PEER               _IOWR('e', 62, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_LNETST		   _IOWR('e', 63, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_LNET_FAULT		   _IOWR('e', 64, IOCTL_LIBCFS_TYPE)
/* lnd ioctls */
#define IOC_LIBCFS_REGISTER_MYNID	   _IOWR('e', 70, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_CLOSE_CONNECTION	   _IOWR('e', 71, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_PUSH_CONNECTION	   _IOWR('e', 72, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_GET_CONN		   _IOWR('e', 73, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_DEL_PEER		   _IOWR('e', 74, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_ADD_PEER		   _IOWR('e', 75, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_GET_PEER		   _IOWR('e', 76, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_DISCOVER                _IOWR('e', 77, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_ADD_INTERFACE	   _IOWR('e', 78, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_DEL_INTERFACE	   _IOWR('e', 79, IOCTL_LIBCFS_TYPE)
#define IOC_LIBCFS_GET_INTERFACE	   _IOWR('e', 80, IOCTL_LIBCFS_TYPE)


/*
 * DLC Specific IOCTL numbers.
 * In order to maintain backward compatibility with any possible external
 * tools which might be accessing the IOCTL numbers, a new group of IOCTL
 * number have been allocated.
 */
#define IOCTL_CONFIG_SIZE		   struct lnet_ioctl_config_data
#define IOC_LIBCFS_ADD_ROUTE		   _IOWR(IOC_LIBCFS_TYPE, 81, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_DEL_ROUTE		   _IOWR(IOC_LIBCFS_TYPE, 82, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_ROUTE		   _IOWR(IOC_LIBCFS_TYPE, 83, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_ADD_NET		   _IOWR(IOC_LIBCFS_TYPE, 84, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_DEL_NET		   _IOWR(IOC_LIBCFS_TYPE, 85, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_NET		   _IOWR(IOC_LIBCFS_TYPE, 86, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_CONFIG_RTR		   _IOWR(IOC_LIBCFS_TYPE, 87, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_ADD_BUF		   _IOWR(IOC_LIBCFS_TYPE, 88, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_BUF		   _IOWR(IOC_LIBCFS_TYPE, 89, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_PEER_INFO	   _IOWR(IOC_LIBCFS_TYPE, 90, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_LNET_STATS	   _IOWR(IOC_LIBCFS_TYPE, 91, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_ADD_PEER_NI		   _IOWR(IOC_LIBCFS_TYPE, 92, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_DEL_PEER_NI		   _IOWR(IOC_LIBCFS_TYPE, 93, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_PEER_NI		   _IOWR(IOC_LIBCFS_TYPE, 94, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_ADD_LOCAL_NI		   _IOWR(IOC_LIBCFS_TYPE, 95, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_DEL_LOCAL_NI		   _IOWR(IOC_LIBCFS_TYPE, 96, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_LOCAL_NI		   _IOWR(IOC_LIBCFS_TYPE, 97, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_SET_NUMA_RANGE	   _IOWR(IOC_LIBCFS_TYPE, 98, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_NUMA_RANGE	   _IOWR(IOC_LIBCFS_TYPE, 99, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_PEER_LIST	   _IOWR(IOC_LIBCFS_TYPE, 100, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_LOCAL_NI_MSG_STATS  _IOWR(IOC_LIBCFS_TYPE, 101, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_SET_HEALHV		   _IOWR(IOC_LIBCFS_TYPE, 102, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_LOCAL_HSTATS	   _IOWR(IOC_LIBCFS_TYPE, 103, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_RECOVERY_QUEUE	   _IOWR(IOC_LIBCFS_TYPE, 104, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_ADD_UDSP		   _IOWR(IOC_LIBCFS_TYPE, 105, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_DEL_UDSP		   _IOWR(IOC_LIBCFS_TYPE, 106, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_UDSP_SIZE	   _IOWR(IOC_LIBCFS_TYPE, 107, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_UDSP		   _IOWR(IOC_LIBCFS_TYPE, 108, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_GET_CONST_UDSP_INFO	   _IOWR(IOC_LIBCFS_TYPE, 109, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_RESET_LNET_STATS	   _IOWR(IOC_LIBCFS_TYPE, 110, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_SET_CONNS_PER_PEER	   _IOWR(IOC_LIBCFS_TYPE, 111, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_SET_PEER		   _IOWR(IOC_LIBCFS_TYPE, 112, IOCTL_CONFIG_SIZE)
#define IOC_LIBCFS_MAX_NR					  112

#endif /* __UAPI_LIBCFS_IOCTL_H__ */
