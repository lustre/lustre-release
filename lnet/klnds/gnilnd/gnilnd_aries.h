/*
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 *   Author: Nic Henke <nic@cray.com>, James Shimek <jshimek@cray.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#ifndef _GNILND_ARIES_H
#define _GNILND_ARIES_H

#include <lnet/lib-lnet.h>

#ifndef _GNILND_HSS_OPS_H
# error "must include gnilnd_hss_ops.h first"
#endif

/* Set HW related values */
#ifdef CONFIG_CRAY_XT
#include <aries/aries_timeouts_gpl.h>
#else
/* from aries_timeouts_gpl.h when building for generic kernel */
#define TIMEOUT_SECS(x)         ((uint64_t)(((x) / 1000.0) + 0.5))
#ifndef TO_GNILND_timeout
#define TO_GNILND_timeout               (60000.000000)
#endif /* TO_GNILND_timeout */
#endif /* CONFIG_CRAY_XT */

#define GNILND_BASE_TIMEOUT        TIMEOUT_SECS(TO_GNILND_timeout)
#define GNILND_CHECKSUM_DEFAULT    0            /* all off for Aries */

#if defined(CONFIG_CRAY_COMPUTE)
#define GNILND_REVERSE_RDMA        GNILND_REVERSE_PUT
#define GNILND_RDMA_DLVR_OPTION    GNI_DLVMODE_PERFORMANCE
#else
#define GNILND_REVERSE_RDMA        GNILND_REVERSE_GET
#define GNILND_RDMA_DLVR_OPTION    GNI_DLVMODE_PERFORMANCE
#define GNILND_SCHED_THREADS       7             /* scheduler threads */
#endif

/* Thread-safe kgni implemented in minor ver 45, code rev 0xb9 */
#define GNILND_KGNI_TS_MINOR_VER 0x45
#define GNILND_TS_ENABLE         1

/* register some memory to allocate a shared mdd */
static inline gni_return_t
kgnilnd_register_smdd_buf(kgn_device_t *dev)
{
	__u32        flags = GNI_MEM_READWRITE;

	if (*kgnilnd_tunables.kgn_bte_relaxed_ordering) {
		flags |= GNI_MEM_RELAXED_PI_ORDERING;
	}

	LIBCFS_ALLOC(dev->gnd_smdd_hold_buf, PAGE_SIZE);
	if (!dev->gnd_smdd_hold_buf) {
		CERROR("Can't allocate smdd hold buffer\n");
		return GNI_RC_ERROR_RESOURCE;
	}

	return kgnilnd_mem_register(dev->gnd_handle,
				    (__u64)dev->gnd_smdd_hold_buf,
				    PAGE_SIZE, NULL, flags,
				    &dev->gnd_smdd_hold_hndl);
}

static inline gni_return_t
kgnilnd_deregister_smdd_buf(kgn_device_t *dev)
{
	gni_return_t rc = kgnilnd_mem_deregister(dev->gnd_handle,
						 &dev->gnd_smdd_hold_hndl, 0);
	LIBCFS_FREE(dev->gnd_smdd_hold_buf, PAGE_SIZE);

	return rc;
}

#endif /* _GNILND_ARIES_H */
